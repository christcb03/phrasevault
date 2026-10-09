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
/// `service`, `level`, and `category` on audit/security records, then the
/// destination's own `extra` labels — PVOS D224), each line the rendered
/// text with `event`, `outcome` and `id` as structured metadata.
pub fn loki_body(items: &[(&Record, View)], extra: &std::collections::BTreeMap<String, String>) -> String {
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
        for (k, v) in extra {
            labels.push_str(&format!(",{}:{}", js(k), js(v)));
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

// ── PVOS D222e: LEEF, RFC 3164, GELF, ECS / _bulk, OCSF, OTLP ──────────────

fn js(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// A field's value as JSON (numbers and booleans stay what they are).
fn jv(v: &crate::Value) -> String {
    match v {
        crate::Value::Str(s) => js(s),
        crate::Value::Int(n) => n.to_string(),
        crate::Value::UInt(n) => n.to_string(),
        crate::Value::Bool(b) => b.to_string(),
    }
}

fn field<'a>(view: &'a View, name: &str) -> Option<&'a crate::Value> {
    view.fields.iter().find(|f| f.name == name).map(|f| &f.value)
}

fn leef_value(s: &str) -> String {
    s.replace('\t', " ").replace('\n', "\\n").replace('\r', "\\r")
}

/// LEEF 2.0 (IBM QRadar): `LEEF:2.0|PhraseVault|<product>|<version>|<event>|x09|`
/// then tab-separated `key=value`: `devTime` (epoch ms), `sev` (1–10),
/// `cat`, `src`/`srcPort`, `usrName`, `outcome`, `msg`, and the fields.
pub fn leef(rec: &Record, view: &View, product: &str, version: &str) -> String {
    let mut attrs = vec![
        format!("devTime={}", rec.ts_ms),
        format!("sev={}", cef_severity(rec.severity).max(1)),
        format!("cat={}", rec.category.as_str()),
        format!("identHostName={}", leef_value(&rec.host)),
        format!("proto={}", leef_value(&rec.service)),
        format!("externalId={}", leef_value(&rec.id)),
    ];
    if let Some(o) = rec.outcome {
        attrs.push(format!("outcome={}", o.as_str()));
    }
    for f in &view.fields {
        let v = f.value.to_string();
        match f.name.as_str() {
            "peer_addr" => {
                let (ip, port) = split_addr(&v);
                attrs.push(format!("src={}", leef_value(&ip)));
                if let Some(p) = port {
                    attrs.push(format!("srcPort={p}"));
                }
            }
            "principal" | "member" if !attrs.iter().any(|a| a.starts_with("usrName=")) => {
                attrs.push(format!("usrName={}", leef_value(&v)));
            }
            name => {
                let key: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
                attrs.push(format!("pv_{key}={}", leef_value(&v)));
            }
        }
    }
    attrs.push(format!("msg={}", leef_value(&view.line())));
    format!(
        "LEEF:2.0|PhraseVault|{}|{}|{}|x09|{}",
        cef_header(product),
        cef_header(version),
        cef_header(&rec.event),
        attrs.join("\t")
    )
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// RFC 3164: `<PRI>Mmm dd hh:mm:ss HOST TAG[PID]: MSG`, in UTC (the format
/// cannot name a zone; RFC 5424 is the default for that reason).
pub fn rfc3164(rec: &Record, msg: &str) -> String {
    let pri = facility(rec) as u16 * 8 + rec.severity.priority() as u16;
    let (_, mo, d, h, mi, s) = crate::time::utc_parts(rec.ts_ms);
    let tag: String = rec.service.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(32).collect();
    let host: String = rec.host.chars().filter(|c| c.is_ascii_graphic()).collect();
    format!(
        "<{pri}>{} {d:>2} {h:02}:{mi:02}:{s:02} {} {}[{}]: {msg}",
        MONTHS[(mo as usize).saturating_sub(1).min(11)],
        if host.is_empty() { "-" } else { &host },
        if tag.is_empty() { "pvfs" } else { &tag },
        rec.pid
    )
}

/// GELF 1.1: the line as `short_message`, every field as `_<name>` (GELF
/// reserves `_id`: the record's id is `_record_id`, a field named `id`
/// `_f_id`).
pub fn gelf(rec: &Record, view: &View) -> String {
    gelf_with(rec, view, usize::MAX, true)
}

/// GELF cut to fit one UDP datagram: the full document if it fits, else the
/// sentence cut and the extra fields left out.
pub fn gelf_udp(rec: &Record, view: &View, max: usize) -> String {
    let full = gelf_with(rec, view, usize::MAX, true);
    if full.len() <= max {
        return full;
    }
    gelf_with(rec, view, 2000, false)
}

fn gelf_with(rec: &Record, view: &View, cut: usize, extras: bool) -> String {
    let line: String = view.line().chars().take(cut).collect();
    let mut o = format!(
        "{{\"version\":\"1.1\",\"host\":{},\"short_message\":{},\"timestamp\":{}.{:03},\"level\":{},\"_event\":{},\"_category\":\"{}\",\"_service\":{},\"_record_id\":{}",
        js(if rec.host.is_empty() { "unknown" } else { &rec.host }),
        js(&line),
        rec.ts_ms / 1000,
        rec.ts_ms % 1000,
        rec.severity.priority(),
        js(&rec.event),
        rec.category.as_str(),
        js(&rec.service),
        js(&rec.id)
    );
    if let Some(out) = rec.outcome {
        o.push_str(&format!(",\"_outcome\":\"{}\"", out.as_str()));
    }
    if extras {
        for f in &view.fields {
            let mut k: String = f.name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' { c } else { '_' }).collect();
            if k == "id" {
                k = "f_id".into();
            }
            o.push_str(&format!(",\"_{k}\":{}", jv(&f.value)));
        }
    }
    o.push('}');
    o
}

/// ECS `event.category` and `event.type` for an event (D222e decision 6).
fn ecs_kind(rec: &Record) -> (&'static str, &'static str) {
    let e = rec.event.as_str();
    let failed = rec.outcome == Some(crate::Outcome::Failure);
    let category = if e.contains(".auth.") || e.contains(".signin.") || e.contains(".session.") {
        "authentication"
    } else if e.contains(".authority.")
        || e.contains(".grant.")
        || e.contains(".member.")
        || e.contains(".invite.")
        || e.contains(".share.")
        || e.contains(".keychain.")
        || e.contains(".access.")
        || e.contains(".control.")
        || e.contains(".desktop.")
    {
        "iam"
    } else if e.contains(".tls.") {
        "network"
    } else if e.contains(".web.") {
        "web"
    } else if e.contains(".boot.") || e.contains(".serve.") || e.contains(".app.") {
        "process"
    } else {
        "host"
    };
    let kind = if failed && rec.category == Category::Security {
        "denied"
    } else if rec.category == Category::Audit {
        "change"
    } else if rec.severity <= Severity::Error {
        "error"
    } else {
        "info"
    };
    (category, kind)
}

/// One Elastic Common Schema document.
pub fn ecs(rec: &Record, view: &View) -> String {
    let (category, etype) = ecs_kind(rec);
    let mut o = format!(
        "{{\"@timestamp\":\"{}\",\"message\":{},\"ecs\":{{\"version\":\"8.11.0\"}},\"event\":{{\"id\":{},\"action\":{},\"kind\":\"{}\",\"category\":[\"{category}\"],\"type\":[\"{etype}\"],\"outcome\":\"{}\",\"severity\":{},\"dataset\":\"pvfs.log\"}},\"log\":{{\"level\":\"{}\",\"logger\":{},\"syslog\":{{\"severity\":{{\"code\":{},\"name\":\"{}\"}}}}}},\"host\":{{\"name\":{}}},\"service\":{{\"name\":{}}},\"process\":{{\"pid\":{}}}",
        format_ts(rec.ts_ms),
        js(&view.line()),
        js(&rec.id),
        js(&rec.event),
        if rec.category == Category::Security { "alert" } else { "event" },
        rec.outcome.map(|o| o.as_str()).unwrap_or("unknown"),
        rec.severity.priority(),
        rec.severity.as_str(),
        js(view.component.as_deref().unwrap_or(&rec.service)),
        rec.severity.priority(),
        rec.severity.as_str(),
        js(&rec.host),
        js(&rec.service),
        rec.pid
    );
    if let Some(addr) = field(view, "peer_addr") {
        let (ip, port) = split_addr(&addr.to_string());
        o.push_str(&format!(",\"source\":{{\"ip\":{}", js(&ip)));
        if let Some(p) = port {
            o.push_str(&format!(",\"port\":{p}"));
        }
        o.push('}');
    }
    if let Some(u) = field(view, "principal").or_else(|| field(view, "member")) {
        o.push_str(&format!(",\"user\":{{\"id\":{}}}", js(&u.to_string())));
    }
    let labels: Vec<String> = view
        .fields
        .iter()
        .filter(|f| !matches!(f.name.as_str(), "peer_addr" | "principal" | "member"))
        .map(|f| format!("{}:{}", js(&f.name), js(&f.value.to_string())))
        .collect();
    if !labels.is_empty() {
        o.push_str(&format!(",\"labels\":{{{}}}", labels.join(",")));
    }
    o.push('}');
    o
}

/// Elasticsearch `_bulk`: an action line and an ECS document per record.
pub fn es_bulk(items: &[(&Record, View)], index: &str) -> String {
    let mut s = String::new();
    for (rec, view) in items {
        s.push_str(&format!("{{\"create\":{{\"_index\":{}}}}}\n", js(index)));
        s.push_str(&ecs(rec, view));
        s.push('\n');
    }
    s
}

/// OCSF 1.1 (D222e decision 7): 3002 Authentication for a refusal or a
/// sign-in, 3005 User Access Management for a change of authority, 0 Base
/// Event otherwise.
pub fn ocsf(rec: &Record, view: &View, product: &str, version: &str) -> String {
    let e = rec.event.as_str();
    let auth = e.contains(".auth.") || e.contains(".signin.") || e.contains(".access.") || e.contains(".control.") || e.contains(".tls.");
    let (class_uid, category_uid, activity_id) = if auth && rec.category != Category::System {
        (3002, 3, 1)
    } else if rec.category == Category::Audit {
        (3005, 3, 1)
    } else {
        (0, 0, 99)
    };
    let severity_id = match rec.severity {
        Severity::Debug | Severity::Info | Severity::Notice => 1,
        Severity::Warning => 3,
        Severity::Error => 4,
        Severity::Critical => 5,
        Severity::Alert | Severity::Emergency => 6,
    };
    let (status_id, status) = match rec.outcome {
        Some(crate::Outcome::Success) => (1, "Success"),
        Some(crate::Outcome::Failure) => (2, "Failure"),
        None => (0, "Unknown"),
    };
    let mut o = format!(
        "{{\"class_uid\":{class_uid},\"category_uid\":{category_uid},\"activity_id\":{activity_id},\"type_uid\":{},\"severity_id\":{severity_id},\"status_id\":{status_id},\"status\":\"{status}\",\"time\":{},\"message\":{},\"metadata\":{{\"version\":\"1.1.0\",\"uid\":{},\"log_name\":{},\"product\":{{\"name\":{},\"vendor_name\":\"PhraseVault\",\"version\":{}}}}},\"device\":{{\"hostname\":{}}}",
        class_uid * 100 + activity_id,
        rec.ts_ms,
        js(&view.line()),
        js(&rec.id),
        js(&rec.event),
        js(product),
        js(version),
        js(&rec.host)
    );
    if let Some(addr) = field(view, "peer_addr") {
        let (ip, port) = split_addr(&addr.to_string());
        o.push_str(&format!(",\"src_endpoint\":{{\"ip\":{}", js(&ip)));
        if let Some(p) = port {
            o.push_str(&format!(",\"port\":{p}"));
        }
        o.push('}');
    }
    if let Some(u) = field(view, "principal").or_else(|| field(view, "member")) {
        o.push_str(&format!(",\"actor\":{{\"user\":{{\"uid\":{}}}}}", js(&u.to_string())));
    }
    let mut unmapped = vec![
        format!("\"pvfs_event\":{}", js(&rec.event)),
        format!("\"pvfs_category\":\"{}\"", rec.category.as_str()),
        format!("\"pvfs_service\":{}", js(&rec.service)),
    ];
    for f in &view.fields {
        if !matches!(f.name.as_str(), "peer_addr" | "principal" | "member") {
            unmapped.push(format!("{}:{}", js(&f.name), jv(&f.value)));
        }
    }
    o.push_str(&format!(",\"unmapped\":{{{}}}", unmapped.join(",")));
    o.push('}');
    o
}

/// OpenTelemetry severity number (1–24) and text.
pub fn otel_severity(s: Severity) -> (u8, &'static str) {
    match s {
        Severity::Debug => (5, "DEBUG"),
        Severity::Info => (9, "INFO"),
        Severity::Notice => (10, "INFO2"),
        Severity::Warning => (13, "WARN"),
        Severity::Error => (17, "ERROR"),
        Severity::Critical => (21, "FATAL"),
        Severity::Alert => (22, "FATAL2"),
        Severity::Emergency => (24, "FATAL4"),
    }
}

fn otel_value(v: &crate::Value) -> String {
    match v {
        crate::Value::Str(s) => format!("{{\"stringValue\":{}}}", js(s)),
        crate::Value::Int(n) => format!("{{\"intValue\":\"{n}\"}}"),
        crate::Value::UInt(n) => format!("{{\"intValue\":\"{n}\"}}"),
        crate::Value::Bool(b) => format!("{{\"boolValue\":{b}}}"),
    }
}

fn otel_kv(k: &str, v: String) -> String {
    format!("{{\"key\":{},\"value\":{v}}}", js(k))
}

/// An OTLP/HTTP JSON logs body (`POST /v1/logs`): one resource per record
/// (service, host, pid), the record's own parts as `pvfs.*` attributes.
pub fn otlp_body(items: &[(&Record, View)]) -> String {
    let mut resources = Vec::new();
    for (rec, view) in items {
        let (num, text) = otel_severity(rec.severity);
        let res_attrs = [
            otel_kv("service.name", format!("{{\"stringValue\":{}}}", js(&rec.service))),
            otel_kv("host.name", format!("{{\"stringValue\":{}}}", js(&rec.host))),
            otel_kv("process.pid", format!("{{\"intValue\":\"{}\"}}", rec.pid)),
            otel_kv("telemetry.sdk.name", "{\"stringValue\":\"pvfs-log\"}".to_string()),
        ];
        let mut attrs = vec![
            otel_kv("pvfs.event", format!("{{\"stringValue\":{}}}", js(&rec.event))),
            otel_kv("pvfs.category", format!("{{\"stringValue\":\"{}\"}}", rec.category.as_str())),
            otel_kv("pvfs.id", format!("{{\"stringValue\":{}}}", js(&rec.id))),
        ];
        if let Some(o) = rec.outcome {
            attrs.push(otel_kv("pvfs.outcome", format!("{{\"stringValue\":\"{}\"}}", o.as_str())));
        }
        for f in &view.fields {
            attrs.push(otel_kv(&f.name, otel_value(&f.value)));
        }
        let ns = format!("{}000000", rec.ts_ms);
        resources.push(format!(
            "{{\"resource\":{{\"attributes\":[{}]}},\"scopeLogs\":[{{\"scope\":{{\"name\":\"pvfs-log\"}},\"logRecords\":[{{\"timeUnixNano\":\"{ns}\",\"observedTimeUnixNano\":\"{ns}\",\"severityNumber\":{num},\"severityText\":\"{text}\",\"body\":{{\"stringValue\":{}}},\"attributes\":[{}]}}]}}]}}",
            res_attrs.join(","),
            js(&view.line()),
            attrs.join(",")
        ));
    }
    format!("{{\"resourceLogs\":[{}]}}", resources.join(","))
}
