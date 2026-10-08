//! What a destination is sent (PVOS D222d decisions 4–7): RFC 5424 syslog
//! (structured data, JSON or CEF as the message), Splunk HEC events, a Loki
//! push body, NDJSON. Every one is made from a record already rendered at the
//! destination's privacy level (`View`), never from the full record.

use crate::{format_ts, to_json, Category, Record, Severity, View};

/// IANA's example enterprise number (RFC 5612) until PhraseVault has its own
/// (D222d, Waiting on Chris).
pub const SD_ID: &str = "pvlog@32473";

fn printable(s: &str, max: usize) -> String {
    let t: String = s.chars().filter(|c| c.is_ascii_graphic()).take(max).collect();
    if t.is_empty() {
        "-".into()
    } else {
        t
    }
}

fn sd_name(s: &str) -> String {
    let t: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic() && !matches!(c, '=' | ']' | '"'))
        .take(32)
        .collect();
    if t.is_empty() {
        "x".into()
    } else {
        t
    }
}

fn sd_value(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '"' | '\\' | ']') {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

/// syslog facility: authpriv (10) for audit and security records, daemon
/// (3) for the rest.
pub fn facility(rec: &Record) -> u8 {
    match rec.category {
        Category::Audit | Category::Security => 10,
        Category::System => 3,
    }
}

/// `<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG`. `msg` is what goes
/// after the structured data (the line, a JSON record, a CEF event);
/// `with_sd` puts the record's parts in `[pvlog@32473 …]`.
pub fn rfc5424(rec: &Record, view: &View, msg: &str, with_sd: bool) -> String {
    let pri = facility(rec) as u16 * 8 + rec.severity.priority() as u16;
    let sd = if with_sd {
        let mut sd = format!("[{SD_ID} event=\"{}\" category=\"{}\"", sd_value(&rec.event), rec.category.as_str());
        if let Some(o) = rec.outcome {
            sd.push_str(&format!(" outcome=\"{}\"", o.as_str()));
        }
        sd.push_str(&format!(" id=\"{}\"", sd_value(&rec.id)));
        for f in &view.fields {
            sd.push_str(&format!(" {}=\"{}\"", sd_name(&f.name), sd_value(&f.value.to_string())));
        }
        sd.push(']');
        sd
    } else {
        "-".into()
    };
    format!(
        "<{pri}>1 {} {} {} {} {} {sd} {msg}",
        format_ts(rec.ts_ms),
        printable(&rec.host, 255),
        printable(&rec.service, 48),
        rec.pid,
        printable(&rec.event, 32),
    )
}

/// CEF severity, 0–10.
pub fn cef_severity(s: Severity) -> u8 {
    match s {
        Severity::Emergency => 10,
        Severity::Alert => 9,
        Severity::Critical => 8,
        Severity::Error => 7,
        Severity::Warning => 5,
        Severity::Notice => 3,
        Severity::Info => 2,
        Severity::Debug => 1,
    }
}

fn cef_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|").replace(['\n', '\r'], " ")
}

fn cef_ext(s: &str) -> String {
    s.replace('\\', "\\\\").replace('=', "\\=").replace('\n', "\\n").replace('\r', "\\r")
}

/// `CEF:0|PhraseVault|<product>|<version>|<event>|<name>|<sev>|<extension>`:
/// `rt`, `dvchost`, `dproc`, `dvcpid`, `act`, `cat`, `outcome`,
/// `externalId`, `msg`; `src`/`spt` from `peer_addr`, `suser` from
/// `principal` or `member`; up to six more fields as `cs1..cs6` with their
/// labels.
pub fn cef(rec: &Record, view: &View, product: &str, version: &str) -> String {
    let line = view.line();
    let name: String = line.chars().take(512).collect();
    let mut ext = vec![
        format!("rt={}", rec.ts_ms),
        format!("dvchost={}", cef_ext(&rec.host)),
        format!("dproc={}", cef_ext(&rec.service)),
        format!("dvcpid={}", rec.pid),
        format!("act={}", cef_ext(&rec.event)),
        format!("cat={}", rec.category.as_str()),
    ];
    if let Some(o) = rec.outcome {
        ext.push(format!("outcome={}", o.as_str()));
    }
    ext.push(format!("externalId={}", cef_ext(&rec.id)));
    let mut custom = 0;
    for f in &view.fields {
        let v = f.value.to_string();
        match f.name.as_str() {
            "peer_addr" => {
                let (ip, port) = split_addr(&v);
                ext.push(format!("src={}", cef_ext(&ip)));
                if let Some(p) = port {
                    ext.push(format!("spt={p}"));
                }
            }
            "principal" | "member" if !ext.iter().any(|e| e.starts_with("suser=")) => {
                ext.push(format!("suser={}", cef_ext(&v)));
            }
            _ if custom < 6 => {
                custom += 1;
                ext.push(format!("cs{custom}Label={}", cef_ext(&f.name)));
                ext.push(format!("cs{custom}={}", cef_ext(&v)));
            }
            _ => {}
        }
    }
    ext.push(format!("msg={}", cef_ext(&line)));
    format!(
        "CEF:0|PhraseVault|{}|{}|{}|{}|{}|{}",
        cef_header(product),
        cef_header(version),
        cef_header(&rec.event),
        cef_header(&name),
        cef_severity(rec.severity),
        ext.join(" ")
    )
}

/// `1.2.3.4:5` → (`1.2.3.4`, 5); `[::1]:5` → (`::1`, 5); anything else whole.
fn split_addr(a: &str) -> (String, Option<u16>) {
    if let Some(rest) = a.strip_prefix('[') {
        if let Some((ip, port)) = rest.split_once("]:") {
            return (ip.to_string(), port.parse().ok());
        }
    }
    match a.rsplit_once(':') {
        Some((ip, port)) if !ip.contains(':') => (ip.to_string(), port.parse().ok()),
        _ => (a.to_string(), None),
    }
}

/// One Splunk HEC event (`/services/collector/event`).
pub fn hec_event(rec: &Record, view: &View, sourcetype: &str, index: Option<&str>) -> String {
    let js = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into());
    let mut o = format!(
        "{{\"time\":{}.{:03},\"host\":{},\"source\":{},\"sourcetype\":{}",
        rec.ts_ms / 1000,
        rec.ts_ms % 1000,
        js(&rec.host),
        js(&rec.service),
        js(sourcetype)
    );
    if let Some(i) = index {
        o.push_str(&format!(",\"index\":{}", js(i)));
    }
    o.push_str(",\"event\":");
    o.push_str(&to_json(rec, view));
    o.push('}');
    o
}

/// A Loki push body: one stream per label set (`job="pvlog"`, `host`,
/// `service`, `level`, and `category` on audit/security records), each line
/// the rendered text with `event`, `outcome` and `id` as structured metadata.
pub fn loki_body(items: &[(&Record, View)]) -> String {
    use std::collections::BTreeMap;
    let js = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into());
    let mut streams: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (rec, view) in items {
        let mut labels = format!(
            "{{\"job\":\"pvlog\",\"host\":{},\"service\":{},\"level\":\"{}\"",
            js(&rec.host),
            js(&rec.service),
            rec.severity.as_str()
        );
        if rec.category != Category::System {
            labels.push_str(&format!(",\"category\":\"{}\"", rec.category.as_str()));
        }
        labels.push('}');
        let mut meta = format!("{{\"event\":{},\"id\":{}", js(&rec.event), js(&rec.id));
        if let Some(o) = rec.outcome {
            meta.push_str(&format!(",\"outcome\":\"{}\"", o.as_str()));
        }
        meta.push('}');
        let value = format!("[\"{}000000\",{},{}]", rec.ts_ms, js(&view.line()), meta);
        streams.entry(labels).or_default().push(value);
    }
    let parts: Vec<String> = streams
        .into_iter()
        .map(|(l, v)| format!("{{\"stream\":{l},\"values\":[{}]}}", v.join(",")))
        .collect();
    format!("{{\"streams\":[{}]}}", parts.join(","))
}

/// Schema-1 records, one per line.
pub fn ndjson(items: &[(&Record, View)]) -> String {
    let mut s = String::new();
    for (rec, view) in items {
        s.push_str(&to_json(rec, view));
        s.push('\n');
    }
    s
}
