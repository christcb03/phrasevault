//! Schema 1 as JSON and logfmt (D222 decisions 1 and 5).
//!
//! JSON, one object per line, keys in this order:
//!
//! ```text
//! {"v":1,"id":"…","seq":7,"ts":"2026-10-07T18:04:05.123Z","host":"mediabox",
//!  "service":"pvfsd","pid":1234,"severity":"warning","event":"pvfs.job.failed",
//!  "category":"system","outcome":"failure","component":"pvfsd","via":"…",
//!  "msg":"watch pass failed: …; retrying","fields":{"job":"watch","error":"…"},
//!  "classes":{"error":"content"}}
//! ```
//!
//! `outcome`, `component` and `via` are left out when empty. `classes` names
//! every field that is not `meta`, so a reader (pvosd relaying a child, a
//! SIEM) knows what was redacted or may still need to be.

use serde_json::Value as J;

use crate::{format_ts, parse_ts, Category, Class, Field, Outcome, Record, Severity, Value, View};

fn js(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

fn value_json(v: &Value) -> String {
    match v {
        Value::Str(s) => js(s),
        Value::Int(n) => n.to_string(),
        Value::UInt(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
    }
}

pub fn to_json(rec: &Record, view: &View) -> String {
    let mut o = String::with_capacity(256 + view.msg.len());
    o.push_str("{\"v\":1,\"id\":");
    o.push_str(&js(&rec.id));
    o.push_str(&format!(",\"seq\":{},\"ts\":\"{}\",\"host\":", rec.seq, format_ts(rec.ts_ms)));
    o.push_str(&js(&rec.host));
    o.push_str(",\"service\":");
    o.push_str(&js(&rec.service));
    o.push_str(&format!(",\"pid\":{},\"severity\":\"{}\",\"event\":", rec.pid, rec.severity.as_str()));
    o.push_str(&js(&rec.event));
    o.push_str(&format!(",\"category\":\"{}\"", rec.category.as_str()));
    if let Some(out) = rec.outcome {
        o.push_str(&format!(",\"outcome\":\"{}\"", out.as_str()));
    }
    if let Some(c) = &view.component {
        o.push_str(",\"component\":");
        o.push_str(&js(c));
    }
    if let Some(v) = &view.via {
        o.push_str(",\"via\":");
        o.push_str(&js(v));
    }
    o.push_str(",\"msg\":");
    o.push_str(&js(&view.msg));
    o.push_str(",\"fields\":{");
    for (i, f) in view.fields.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&js(&f.name));
        o.push(':');
        o.push_str(&value_json(&f.value));
    }
    o.push('}');
    let classed: Vec<&Field> = view.fields.iter().filter(|f| f.class != Class::Meta).collect();
    if !classed.is_empty() {
        o.push_str(",\"classes\":{");
        for (i, f) in classed.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push_str(&js(&f.name));
            o.push_str(&format!(":\"{}\"", f.class.as_str()));
        }
        o.push('}');
    }
    o.push('}');
    o
}

/// The `fields` object in the order it was written (serde_json's own map
/// sorts its keys unless a feature this workspace does not turn on is set).
struct Ordered(Vec<(String, J)>);

impl<'de> serde::Deserialize<'de> for Ordered {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> Result<Ordered, A::Error> {
                let mut v = Vec::new();
                while let Some((k, val)) = m.next_entry::<String, J>()? {
                    v.push((k, val));
                }
                Ok(Ordered(v))
            }
        }
        d.deserialize_map(V)
    }
}

#[derive(serde::Deserialize)]
struct Wire {
    v: u64,
    id: String,
    #[serde(default)]
    seq: u64,
    ts: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    service: String,
    #[serde(default)]
    pid: u32,
    severity: String,
    event: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    component: Option<String>,
    #[serde(default)]
    via: Option<String>,
    msg: String,
    #[serde(default)]
    fields: Option<Ordered>,
    #[serde(default)]
    classes: Option<std::collections::HashMap<String, String>>,
}

/// A schema-1 JSON line back into a record; `None` for anything else.
pub fn parse_json(line: &str) -> Option<Record> {
    let line = line.trim();
    if !line.starts_with('{') {
        return None;
    }
    let w: Wire = serde_json::from_str(line).ok()?;
    if w.v != 1 {
        return None;
    }
    let mut fields = Vec::new();
    for (name, v) in w.fields.map(|o| o.0).unwrap_or_default() {
        let value = match v {
            J::String(s) => Value::Str(s),
            J::Bool(b) => Value::Bool(b),
            J::Number(n) => {
                if let Some(u) = n.as_u64() {
                    Value::UInt(u)
                } else if let Some(i) = n.as_i64() {
                    Value::Int(i)
                } else {
                    Value::Str(n.to_string())
                }
            }
            other => Value::Str(other.to_string()),
        };
        let class = w
            .classes
            .as_ref()
            .and_then(|c| c.get(&name))
            .and_then(|c| Class::parse(c))
            .unwrap_or(Class::Meta);
        fields.push(Field { name, class, value });
    }
    Some(Record {
        id: w.id,
        seq: w.seq,
        ts_ms: parse_ts(&w.ts)?,
        host: w.host,
        service: w.service,
        pid: w.pid,
        severity: Severity::parse(&w.severity)?,
        event: w.event,
        category: w.category.as_deref().and_then(Category::parse).unwrap_or(Category::System),
        outcome: w.outcome.as_deref().and_then(Outcome::parse),
        component: w.component,
        via: w.via,
        msg: w.msg,
        fields,
    })
}

fn lf(v: &str) -> String {
    let plain = !v.is_empty()
        && v.chars().all(|c| !c.is_whitespace() && c != '"' && c != '=' && c != '\\' && !c.is_control());
    if plain {
        v.to_string()
    } else {
        let mut o = String::with_capacity(v.len() + 2);
        o.push('"');
        for c in v.chars() {
            match c {
                '"' => o.push_str("\\\""),
                '\\' => o.push_str("\\\\"),
                '\n' => o.push_str("\\n"),
                '\r' => o.push_str("\\r"),
                '\t' => o.push_str("\\t"),
                c => o.push(c),
            }
        }
        o.push('"');
        o
    }
}

/// `ts=… severity=… event=… service=… component=… msg="…" k=v …` — field
/// names that would collide with the record's own keys get an `f_` prefix.
pub fn to_logfmt(rec: &Record, view: &View) -> String {
    const OWN: &[&str] =
        &["ts", "id", "seq", "host", "service", "pid", "severity", "event", "category", "outcome", "component", "via", "msg"];
    let mut parts = vec![
        format!("ts={}", format_ts(rec.ts_ms)),
        format!("severity={}", rec.severity.as_str()),
        format!("event={}", lf(&rec.event)),
        format!("service={}", lf(&rec.service)),
    ];
    if rec.category != Category::System {
        parts.push(format!("category={}", rec.category.as_str()));
    }
    if let Some(o) = rec.outcome {
        parts.push(format!("outcome={}", o.as_str()));
    }
    if let Some(v) = &view.via {
        parts.push(format!("via={}", lf(v)));
    }
    if let Some(c) = &view.component {
        parts.push(format!("component={}", lf(c)));
    }
    parts.push(format!("msg={}", lf(&view.msg)));
    for f in &view.fields {
        let k = if OWN.contains(&f.name.as_str()) { format!("f_{}", f.name) } else { f.name.clone() };
        parts.push(format!("{k}={}", lf(&f.value.to_string())));
    }
    parts.push(format!("id={}", rec.id));
    parts.join(" ")
}
