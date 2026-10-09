//! PVOS D226 — the questions a new destination needs, asked through the
//! caller's own prompt (`pvfs log destinations add`, `pvfs-companion log
//! add`), so both ask the same things in the same order.

use super::config::{Destination, Kind, TlsSettings};
use super::DEFAULT_ES_INDEX;

/// A destination as answered, and the token to keep for it (empty = none).
/// The caller stores the token (a 0600 file, the Keychain) and sets
/// `secret`.
pub struct Asked {
    pub destination: Destination,
    pub token: String,
}

/// `ask(question, default)` returns the answer (the default when it is
/// left blank); `confirm(question)` a yes or no. `taken` are the names in
/// use.
pub fn ask_destination(
    taken: &[String],
    ask: &mut dyn FnMut(&str, Option<&str>) -> Result<String, String>,
    confirm: &mut dyn FnMut(&str) -> Result<bool, String>,
) -> Result<Asked, String> {
    let default_name = if taken.iter().any(|n| n == "logs") { None } else { Some("logs") };
    let name = ask("name for it (letters, digits, - and _)", default_name)?;
    if taken.iter().any(|n| *n == name) {
        return Err(format!("there is already a destination named {name}"));
    }
    let mut q = "type: loki, splunk_hec, syslog, https_json, gelf, elasticsearch or otlp".to_string();
    let mut kind = None;
    for _ in 0..3 {
        let k = ask(&q, Some("loki"))?;
        match Kind::parse(&k) {
            Some(found) => {
                kind = Some(found);
                break;
            }
            None => q = format!("{k:?} is not one of them — type: loki, splunk_hec, syslog, https_json, gelf, elasticsearch or otlp"),
        }
    }
    let kind = kind.ok_or("no type given")?;
    let mut d = Destination {
        name: name.clone(),
        enabled: true,
        kind,
        url: None,
        address: None,
        transport: None,
        format: None,
        index: None,
        sourcetype: None,
        header: None,
        privacy: "minimal".into(),
        min_severity: "info".into(),
        categories: vec![],
        services: vec![],
        tls: TlsSettings::default(),
        secret: None,
        labels: Default::default(),
        spool_mb: 256,
    };
    let mut uses_tls = false;
    let mut token_wanted = false;
    match kind {
        Kind::Syslog => {
            let t = ask("transport: tls, tcp or udp", Some("tls"))?;
            uses_tls = t == "tls";
            d.transport = Some(t);
            d.address = Some(ask("the receiver, host:port", Some(if uses_tls { "siem.example.com:6514" } else { "siem.example.com:514" }))?);
            d.format = Some(ask("format: rfc5424, cef, leef, json or rfc3164", Some("rfc5424"))?);
        }
        Kind::Gelf => {
            let t = ask("transport: udp, tcp or http", Some("udp"))?;
            if t == "http" {
                d.url = Some(ask("Graylog's GELF HTTP URL", Some("http://graylog.example.com:12201/gelf"))?);
            } else {
                d.address = Some(ask("the GELF input, host:port", Some("graylog.example.com:12201"))?);
            }
            d.transport = Some(t);
        }
        Kind::Elasticsearch => {
            d.url = Some(ask("Elasticsearch / OpenSearch URL", Some("https://elastic.example.com:9200"))?);
            d.index = Some(ask("index or data stream", Some(DEFAULT_ES_INDEX))?);
            token_wanted = true;
        }
        Kind::Otlp => {
            d.url = Some(ask("the OTLP/HTTP endpoint (an OpenTelemetry Collector)", Some("http://otel-collector.example.com:4318"))?);
        }
        Kind::SplunkHec => {
            d.url = Some(ask("the HEC URL", Some("https://splunk.example.com:8088"))?);
            let idx = ask("Splunk index (blank = the token's default)", Some(""))?;
            d.index = Some(idx).filter(|i| !i.is_empty());
            token_wanted = true;
        }
        Kind::Loki => {
            d.url = Some(ask("Loki's URL", Some("http://192.168.1.83:3100"))?);
            // PVOS D224 — fixed stream labels, e.g. env=prod for the alerts.
            let extra = ask("extra stream labels, name=value, comma-separated (fixed values such as env=prod; blank = none)", Some(""))?;
            for pair in extra.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let (k, v) = pair.split_once('=').ok_or_else(|| format!("label {pair:?}: write it as name=value"))?;
                d.labels.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        Kind::HttpsJson => {
            d.url = Some(ask("the receiver's URL", None)?);
            d.format = Some(ask("format: schema1 (PVFS's own), ecs (Elastic Common Schema) or ocsf", Some("schema1"))?);
        }
    }
    if let Some(u) = &d.url {
        uses_tls = u.trim().starts_with("https://");
    }
    let token = if token_wanted && kind == Kind::Elasticsearch {
        ask("an API key (sent as ApiKey …; or type \"Basic <base64>\")", None)?
    } else if token_wanted {
        ask("the HEC token", None)?
    } else if kind != Kind::Syslog && !(kind == Kind::Gelf && d.url.is_none()) {
        ask("a token to send, if the receiver wants one (blank = none)", Some(""))?
    } else {
        String::new()
    };
    if uses_tls {
        let how = ask("verify the receiver's certificate by: roots (public CAs), ca (a CA file) or pin (its SHA-256)", Some("roots"))?;
        match how.as_str() {
            "ca" => d.tls.ca_file = Some(ask("the CA file (PEM)", None)?),
            "pin" => d.tls.pin_sha256 = Some(ask("the certificate's SHA-256 (openssl x509 -fingerprint -sha256)", None)?),
            _ => {}
        }
    }
    let privacy = ask("privacy: minimal (no names, paths or addresses except on security events), identified or full", Some("minimal"))?;
    if privacy != "minimal" {
        let what = if privacy == "full" { "everything, file names and paths included," } else { "names, emails and addresses" };
        if !confirm(&format!("this sends {what} to {name} — sure?"))? {
            return Err("not added".into());
        }
    }
    d.privacy = privacy;
    d.min_severity = ask("the least severe record to send: error, warning, notice or info", Some("info"))?;
    let cats = ask("categories: all, or a list of system, audit, security", Some("all"))?;
    if cats != "all" {
        d.categories = cats.split(',').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect();
    }
    Ok(Asked { destination: d, token: token.trim().to_string() })
}
