//! Destinations, as configured (PVOS D222d decision 10): one schema for
//! PVFS's file and PVOS's forest record.

use serde::{Deserialize, Serialize};

use crate::{Category, Privacy, Severity};

/// The stream labels a Loki push always carries; a destination's own
/// `labels` may not name them (PVOS D224).
pub const LOKI_SET_LABELS: &[&str] = &["job", "host", "service", "level", "category"];

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ShipConfig {
    #[serde(default = "one")]
    pub v: u32,
    #[serde(default)]
    pub destinations: Vec<Destination>,
    /// PVFS: a file holding the 32-byte pseudonym key (raw or hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudonym_key_file: Option<String>,
}

fn one() -> u32 {
    1
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Syslog,
    SplunkHec,
    Loki,
    HttpsJson,
    /// PVOS D222e — Graylog's GELF over udp, tcp or http.
    Gelf,
    /// PVOS D222e — Elasticsearch / OpenSearch `_bulk`, ECS documents.
    Elasticsearch,
    /// PVOS D222e — OpenTelemetry logs, OTLP/HTTP JSON.
    Otlp,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Syslog => "syslog",
            Kind::SplunkHec => "splunk_hec",
            Kind::Loki => "loki",
            Kind::HttpsJson => "https_json",
            Kind::Gelf => "gelf",
            Kind::Elasticsearch => "elasticsearch",
            Kind::Otlp => "otlp",
        }
    }
    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "syslog" => Kind::Syslog,
            "splunk_hec" | "splunk" | "hec" => Kind::SplunkHec,
            "loki" => Kind::Loki,
            "https_json" | "http_json" | "json" | "webhook" => Kind::HttpsJson,
            "gelf" | "graylog" => Kind::Gelf,
            "elasticsearch" | "elastic" | "opensearch" => Kind::Elasticsearch,
            "otlp" | "opentelemetry" | "otel" => Kind::Otlp,
            _ => return None,
        })
    }
}

/// TLS for a destination (decision 8): verified always — by the system's
/// roots, or only by `ca_file`'s, or only by a pinned certificate.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TlsSettings {
    /// PEM file of the CA(s) to trust instead of the public roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
    /// SHA-256 of the server certificate (hex, colons allowed): exactly that
    /// certificate is accepted (a self-signed receiver).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Destination {
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(rename = "type")]
    pub kind: Kind,
    /// HEC, Loki, HTTPS JSON: `http(s)://host[:port][/path]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// syslog: `host:port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// syslog: `udp`, `tcp` or `tls` (default `tls`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// syslog: `rfc5424` (default), `json` or `cef`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// HEC: the index (else the token's default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    /// HEC: the sourcetype (default `pvfs:json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sourcetype: Option<String>,
    /// HTTPS JSON: the header the secret goes in (default `Authorization`,
    /// sent as `Bearer <secret>`; any other name is sent as `<name>: <secret>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// `minimal` (default), `identified` or `full` (D222 decision 3b).
    #[serde(default = "minimal")]
    pub privacy: String,
    /// The least severe record sent (default `info`).
    #[serde(default = "info")]
    pub min_severity: String,
    /// `system`, `audit`, `security`; empty = all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// Only these services (`pvfsd`, `pvosd`, `app:iac`, …); empty = all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    #[serde(default, skip_serializing_if = "tls_is_default")]
    pub tls: TlsSettings,
    /// PVFS: a file (0600) holding the token. PVOS keeps tokens in its
    /// keychain and hands them over itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Loki only (PVOS D224): extra stream labels on every push, such as
    /// `{"env": "prod"}`. Each distinct set is a Loki stream, so fixed
    /// values only (an environment, a site), never per-record ones.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub labels: std::collections::BTreeMap<String, String>,
    /// The spool's cap in MiB (default 256).
    #[serde(default = "spool_default")]
    pub spool_mb: u64,
}

fn yes() -> bool {
    true
}
fn minimal() -> String {
    "minimal".into()
}
fn info() -> String {
    "info".into()
}
fn spool_default() -> u64 {
    256
}
fn tls_is_default(t: &TlsSettings) -> bool {
    *t == TlsSettings::default()
}

/// syslog's three transports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyslogTransport {
    Udp,
    Tcp,
    Tls,
}

/// syslog's payloads (D222d decision 4; LEEF and RFC 3164 since D222e).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyslogFormat {
    Rfc5424,
    Json,
    Cef,
    Leef,
    /// The older BSD framing (`<PRI>Mmm dd hh:mm:ss HOST TAG[PID]: MSG`).
    Rfc3164,
}

/// What an `https_json` destination posts (PVOS D222e decision 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpFormat {
    /// The schema-1 record (doc 32).
    Schema1,
    /// Elastic Common Schema documents.
    Ecs,
    /// OCSF events.
    Ocsf,
}

impl Destination {
    pub fn privacy(&self) -> Privacy {
        Privacy::parse(&self.privacy).unwrap_or(Privacy::Minimal)
    }
    pub fn min_severity(&self) -> Severity {
        Severity::parse(&self.min_severity).unwrap_or(Severity::Info)
    }
    pub fn syslog_transport(&self) -> SyslogTransport {
        match self.transport.as_deref().unwrap_or("tls").trim().to_ascii_lowercase().as_str() {
            "udp" => SyslogTransport::Udp,
            "tcp" => SyslogTransport::Tcp,
            _ => SyslogTransport::Tls,
        }
    }
    pub fn syslog_format(&self) -> SyslogFormat {
        match self.format.as_deref().unwrap_or("rfc5424").trim().to_ascii_lowercase().as_str() {
            "json" => SyslogFormat::Json,
            "cef" => SyslogFormat::Cef,
            "leef" => SyslogFormat::Leef,
            "rfc3164" | "bsd" => SyslogFormat::Rfc3164,
            _ => SyslogFormat::Rfc5424,
        }
    }
    pub fn http_format(&self) -> HttpFormat {
        match self.format.as_deref().unwrap_or("schema1").trim().to_ascii_lowercase().as_str() {
            "ecs" => HttpFormat::Ecs,
            "ocsf" => HttpFormat::Ocsf,
            _ => HttpFormat::Schema1,
        }
    }
    /// GELF's transport: `udp` (default), `tcp` or `http`.
    pub fn gelf_transport(&self) -> &str {
        match self.transport.as_deref().map(|t| t.trim().to_ascii_lowercase()) {
            Some(t) if t == "tcp" => "tcp",
            Some(t) if t == "http" || t == "https" => "http",
            _ => "udp",
        }
    }

    /// Whether this destination takes `rec` (decision 1). A record about this
    /// destination itself (its `destination` field) never goes to it.
    pub fn takes(&self, rec: &crate::Record) -> bool {
        if rec.severity > self.min_severity() {
            return false;
        }
        if !self.categories.is_empty() && !self.categories.iter().any(|c| Category::parse(c) == Some(rec.category)) {
            return false;
        }
        if !self.services.is_empty() && !self.services.iter().any(|s| s == &rec.service) {
            return false;
        }
        !rec
            .fields
            .iter()
            .any(|f| f.name == "destination" && f.value.to_string() == self.name)
    }

    /// Everything wrong with it, empty when it can be used.
    pub fn problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        let n = &self.name;
        if n.is_empty() || !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') || n.len() > 40 {
            p.push(format!("name {n:?}: letters, digits, '-' and '_' only, at most 40"));
        }
        if Privacy::parse(&self.privacy).is_none() {
            p.push(format!("{n}: privacy {:?} is not full, identified or minimal", self.privacy));
        }
        if Severity::parse(&self.min_severity).is_none() {
            p.push(format!("{n}: min_severity {:?} is not a severity", self.min_severity));
        }
        for c in &self.categories {
            if Category::parse(c).is_none() {
                p.push(format!("{n}: category {c:?} is not system, audit or security"));
            }
        }
        if !self.labels.is_empty() && self.kind != Kind::Loki {
            p.push(format!("{n}: labels are for a loki destination only"));
        }
        for (k, v) in &self.labels {
            let name_ok = k.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !k.starts_with("__");
            if !name_ok {
                p.push(format!("{n}: label {k:?} is not a label name (letters, digits and _, not starting with a digit or __)"));
            } else if LOKI_SET_LABELS.contains(&k.as_str()) {
                p.push(format!("{n}: label {k:?} is set by PVFS itself"));
            }
            if v.is_empty() || v.chars().count() > 128 {
                p.push(format!("{n}: label {k}'s value must be 1 to 128 characters"));
            }
        }
        match self.kind {
            Kind::Syslog => {
                match self.address.as_deref() {
                    Some(a) if a.rsplit_once(':').is_some_and(|(h, port)| !h.is_empty() && port.parse::<u16>().is_ok()) => {}
                    _ => p.push(format!("{n}: syslog needs an address host:port")),
                }
                if let Some(t) = &self.transport {
                    if !matches!(t.trim().to_ascii_lowercase().as_str(), "udp" | "tcp" | "tls") {
                        p.push(format!("{n}: transport {t:?} is not udp, tcp or tls"));
                    }
                }
                if let Some(f) = &self.format {
                    if !matches!(f.trim().to_ascii_lowercase().as_str(), "rfc5424" | "json" | "cef" | "leef" | "rfc3164" | "bsd") {
                        p.push(format!("{n}: format {f:?} is not rfc5424, json, cef, leef or rfc3164"));
                    }
                }
            }
            Kind::Gelf if self.gelf_transport() != "http" => {
                match self.address.as_deref() {
                    Some(a) if a.rsplit_once(':').is_some_and(|(h, port)| !h.is_empty() && port.parse::<u16>().is_ok()) => {}
                    _ => p.push(format!("{n}: gelf over {} needs an address host:port", self.gelf_transport())),
                }
                if let Some(t) = &self.transport {
                    if !matches!(t.trim().to_ascii_lowercase().as_str(), "udp" | "tcp" | "http" | "https") {
                        p.push(format!("{n}: transport {t:?} is not udp, tcp or http"));
                    }
                }
            }
            Kind::SplunkHec | Kind::Loki | Kind::HttpsJson | Kind::Gelf | Kind::Elasticsearch | Kind::Otlp => {
                match self.url.as_deref().map(super::http::Url::parse) {
                    Some(Ok(_)) => {}
                    Some(Err(e)) => p.push(format!("{n}: url: {e}")),
                    None => p.push(format!("{n}: {} needs a url", self.kind.as_str())),
                }
                if self.kind == Kind::HttpsJson {
                    if let Some(f) = &self.format {
                        if !matches!(f.trim().to_ascii_lowercase().as_str(), "schema1" | "json" | "ecs" | "ocsf") {
                            p.push(format!("{n}: format {f:?} is not schema1, ecs or ocsf"));
                        }
                    }
                }
            }
        }
        if let Some(pin) = &self.tls.pin_sha256 {
            if super::tls::parse_pin(pin).is_none() {
                p.push(format!("{n}: pin_sha256 is not 64 hex characters"));
            }
        }
        p
    }
}

impl ShipConfig {
    pub fn parse(text: &str) -> Result<ShipConfig, String> {
        let c: ShipConfig = serde_json::from_str(text).map_err(|e| format!("not a destinations file: {e}"))?;
        if c.v != 1 {
            return Err(format!("destinations file version {} (this build reads 1)", c.v));
        }
        let mut seen = std::collections::HashSet::new();
        for d in &c.destinations {
            if !seen.insert(d.name.clone()) {
                return Err(format!("two destinations named {:?}", d.name));
            }
        }
        Ok(c)
    }

    pub fn to_text(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default() + "\n"
    }
}

/// Where PVFS reads its destinations (decision 11): `$PVFS_LOG_DESTINATIONS`,
/// else `/etc/pvfs/log-destinations.json` when it exists, else
/// `~/.config/pvfs/log-destinations.json`.
pub fn config_path() -> std::path::PathBuf {
    if let Some(p) = std::env::var_os("PVFS_LOG_DESTINATIONS") {
        if !p.is_empty() {
            return p.into();
        }
    }
    let etc = std::path::PathBuf::from("/etc/pvfs/log-destinations.json");
    if etc.exists() {
        return etc;
    }
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default();
    home.join(".config/pvfs/log-destinations.json")
}
