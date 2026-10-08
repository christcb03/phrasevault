//! One destination's sender (PVOS D222d decisions 2, 3, 15): a thread that
//! sends what its spool holds, in batches, rendered at the destination's
//! privacy level at send time; backs off after a failure; and says once when
//! the destination has been failing for a while, and when it is back.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::config::{Destination, HttpFormat, Kind, SyslogFormat};
use super::format;
use super::spool::Spool;
use crate::{parse_json, render, to_json, Record, View};

pub const BATCH_LINES: usize = 500;
pub const BATCH_BYTES: usize = 1 << 20;
const BACKOFF_MAX: Duration = Duration::from_secs(300);

/// What `serve status`, the census and Settings show for a destination.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Health {
    pub sent: u64,
    pub dropped: u64,
    pub pending_bytes: u64,
    pub last_ok_ms: u64,
    pub last_error: Option<String>,
    pub last_error_ms: u64,
    /// Set while the destination has been failing past the threshold and
    /// that has been logged.
    pub failing_reported: bool,
}

pub struct Dest {
    pub cfg: Destination,
    pub token: Option<String>,
    pub key: Option<[u8; 32]>,
    pub product: String,
    pub version: String,
    pub spool: Mutex<Spool>,
    pub health: Mutex<Health>,
    pub stop: AtomicBool,
    pub started_ms: u64,
    pub failing_after_ms: u64,
}

impl Dest {
    /// Offer a record: spooled (full detail) if this destination takes it.
    pub fn offer(&self, rec: &Record) {
        if !self.cfg.takes(rec) {
            return;
        }
        let line = to_json(rec, &render(rec, crate::Privacy::Full, None));
        let mut sp = self.spool.lock().unwrap_or_else(|p| p.into_inner());
        if sp.append(&line).is_err() {
            sp.dropped += 1;
        }
    }

    pub fn health(&self) -> Health {
        let mut h = self.health.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let sp = self.spool.lock().unwrap_or_else(|p| p.into_inner());
        h.dropped = sp.dropped;
        h.pending_bytes = sp.pending_bytes();
        h
    }
}

/// Send these records now, as this destination wants them.
pub fn deliver(d: &Dest, recs: &[Record]) -> Result<(), String> {
    let privacy = d.cfg.privacy();
    let items: Vec<(&Record, View)> = recs.iter().map(|r| (r, render(r, privacy, d.key.as_ref()))).collect();
    match d.cfg.kind {
        Kind::Syslog => {
            let fmt = d.cfg.syslog_format();
            let msgs: Vec<String> = items
                .iter()
                .map(|(r, v)| match fmt {
                    SyslogFormat::Rfc5424 => format::rfc5424(r, v, &v.line(), true),
                    SyslogFormat::Json => format::rfc5424(r, v, &to_json(r, v), false),
                    SyslogFormat::Cef => format::rfc5424(r, v, &format::cef(r, v, &d.product, &d.version), false),
                    SyslogFormat::Leef => format::rfc5424(r, v, &format::leef(r, v, &d.product, &d.version), false),
                    SyslogFormat::Rfc3164 => format::rfc3164(r, &v.line()),
                })
                .collect();
            super::syslog::send(
                d.cfg.address.as_deref().unwrap_or_default(),
                d.cfg.syslog_transport(),
                &d.cfg.tls,
                &msgs,
            )
        }
        Kind::SplunkHec => {
            let url = super::http::Url::parse(d.cfg.url.as_deref().unwrap_or_default())?;
            let st = d.cfg.sourcetype.as_deref().unwrap_or("pvfs:json");
            let body: Vec<String> = items.iter().map(|(r, v)| format::hec_event(r, v, st, d.cfg.index.as_deref())).collect();
            let token = d.token.as_deref().ok_or("no HEC token")?;
            let (code, text) = super::http::post(
                &url,
                &url.path_or("/services/collector/event"),
                &d.cfg.tls,
                &[("Authorization".into(), format!("Splunk {token}"))],
                body.join("\n").as_bytes(),
            )?;
            if code == 200 && (text.contains("\"code\":0") || text.contains("Success")) {
                Ok(())
            } else {
                Err(format!("HEC answered {code}: {}", text.chars().take(200).collect::<String>()))
            }
        }
        Kind::Loki => {
            let url = super::http::Url::parse(d.cfg.url.as_deref().unwrap_or_default())?;
            let mut headers = Vec::new();
            if let Some(t) = &d.token {
                headers.push(("Authorization".to_string(), format!("Bearer {t}")));
            }
            let (code, text) = super::http::post(
                &url,
                &url.path_or("/loki/api/v1/push"),
                &d.cfg.tls,
                &headers,
                format::loki_body(&items).as_bytes(),
            )?;
            if (200..300).contains(&code) {
                Ok(())
            } else {
                Err(format!("Loki answered {code}: {}", text.chars().take(200).collect::<String>()))
            }
        }
        Kind::HttpsJson => {
            let url = super::http::Url::parse(d.cfg.url.as_deref().unwrap_or_default())?;
            let headers = auth_headers(d, "Bearer");
            let body = match d.cfg.http_format() {
                HttpFormat::Schema1 => format::ndjson(&items),
                HttpFormat::Ecs => items.iter().map(|(r, v)| format::ecs(r, v) + "\n").collect(),
                HttpFormat::Ocsf => items.iter().map(|(r, v)| format::ocsf(r, v, &d.product, &d.version) + "\n").collect(),
            };
            let (code, text) = super::http::post(&url, &url.path_or("/"), &d.cfg.tls, &headers, body.as_bytes())?;
            if (200..300).contains(&code) {
                Ok(())
            } else {
                Err(format!("the receiver answered {code}: {}", text.chars().take(200).collect::<String>()))
            }
        }
        Kind::Gelf => match d.cfg.gelf_transport() {
            "http" => {
                let url = super::http::Url::parse(d.cfg.url.as_deref().unwrap_or_default())?;
                let docs: Vec<String> = items.iter().map(|(r, v)| format::gelf(r, v)).collect();
                super::gelf::send_http(&url, &d.cfg.tls, &auth_headers(d, "Bearer"), &docs)
            }
            "tcp" => {
                let docs: Vec<String> = items.iter().map(|(r, v)| format::gelf(r, v)).collect();
                super::gelf::send_tcp(d.cfg.address.as_deref().unwrap_or_default(), &docs)
            }
            _ => {
                let docs: Vec<String> = items.iter().map(|(r, v)| format::gelf_udp(r, v, super::gelf::UDP_MAX)).collect();
                super::gelf::send_udp(d.cfg.address.as_deref().unwrap_or_default(), &docs)
            }
        },
        Kind::Elasticsearch => {
            let url = super::http::Url::parse(d.cfg.url.as_deref().unwrap_or_default())?;
            let index = d.cfg.index.as_deref().unwrap_or("pvfs-logs");
            let (code, text) = super::http::post_typed(
                &url,
                &url.path_or("/_bulk"),
                "application/x-ndjson",
                &d.cfg.tls,
                &auth_headers(d, "ApiKey"),
                format::es_bulk(&items, index).as_bytes(),
            )?;
            if (200..300).contains(&code) && !text.contains("\"errors\":true") {
                Ok(())
            } else {
                Err(format!("Elasticsearch answered {code}: {}", text.chars().take(300).collect::<String>()))
            }
        }
        Kind::Otlp => {
            let url = super::http::Url::parse(d.cfg.url.as_deref().unwrap_or_default())?;
            let (code, text) = super::http::post(
                &url,
                &url.path_or("/v1/logs"),
                &d.cfg.tls,
                &auth_headers(d, "Bearer"),
                format::otlp_body(&items).as_bytes(),
            )?;
            if (200..300).contains(&code) {
                Ok(())
            } else {
                Err(format!("the OTLP receiver answered {code}: {}", text.chars().take(200).collect::<String>()))
            }
        }
    }
}

/// The sender thread.
pub fn run(d: Arc<Dest>) {
    let mut backoff = Duration::from_secs(1);
    while !d.stop.load(Ordering::Relaxed) {
        let (lines, pos) = d.spool.lock().unwrap_or_else(|p| p.into_inner()).read_batch(BATCH_LINES, BATCH_BYTES);
        if lines.is_empty() {
            sleep_unless_stopped(&d, Duration::from_secs(1));
            continue;
        }
        let recs: Vec<Record> = lines.iter().filter_map(|l| parse_json(l)).collect();
        let res = if recs.is_empty() { Ok(()) } else { deliver(&d, &recs) };
        let now = crate::time::now_ms();
        match res {
            Ok(()) => {
                let _ = d.spool.lock().unwrap_or_else(|p| p.into_inner()).commit(pos);
                let was_failing = {
                    let mut h = d.health.lock().unwrap_or_else(|p| p.into_inner());
                    h.sent += recs.len() as u64;
                    h.last_ok_ms = now;
                    std::mem::take(&mut h.failing_reported)
                };
                if was_failing {
                    super::note_recovered(&d.cfg.name);
                }
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                let report = {
                    let mut h = d.health.lock().unwrap_or_else(|p| p.into_inner());
                    h.last_error = Some(e.clone());
                    h.last_error_ms = now;
                    let since = if h.last_ok_ms > 0 { h.last_ok_ms } else { d.started_ms };
                    if !h.failing_reported && now.saturating_sub(since) >= d.failing_after_ms {
                        h.failing_reported = true;
                        Some(now.saturating_sub(since))
                    } else {
                        None
                    }
                };
                if let Some(for_ms) = report {
                    super::note_failing(&d.cfg.name, &e, for_ms);
                }
                sleep_unless_stopped(&d, backoff);
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

fn sleep_unless_stopped(d: &Dest, total: Duration) {
    let step = Duration::from_millis(100);
    let mut slept = Duration::ZERO;
    while slept < total && !d.stop.load(Ordering::Relaxed) {
        std::thread::sleep(step);
        slept += step;
    }
}

/// The token as its header (PVOS D222e): `header` (default `Authorization`);
/// for `Authorization`, `<scheme> <token>` unless the token already names
/// its scheme (`Basic …`, `ApiKey …`, `Bearer …`).
fn auth_headers(d: &Dest, scheme: &str) -> Vec<(String, String)> {
    let Some(t) = &d.token else { return Vec::new() };
    let name = d.cfg.header.clone().unwrap_or_else(|| "Authorization".into());
    let value = if name.eq_ignore_ascii_case("authorization") && !t.contains(' ') {
        format!("{scheme} {t}")
    } else {
        t.clone()
    };
    vec![(name, value)]
}
