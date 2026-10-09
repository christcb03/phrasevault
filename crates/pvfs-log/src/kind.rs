//! PVOS D229 — what kind of failure a record is: `error_kind`, on every
//! record at warning or above.
//!
//! A destination at `minimal` privacy drops an error's text (it can name a
//! path: D222 3c), so a shipped failure used to say only *that* something
//! failed. The kind is a fixed vocabulary — `<class>:<detail>`, `meta`,
//! never a path or a name — so it survives every privacy level and a search
//! can group failures: `error_kind=~"network.*"`.
//!
//! Where it comes from, first match wins:
//! 1. the call site, when it passes `error_kind = "…"`;
//! 2. the event name, for the generic shapes (`….panicked`, `…_slow`,
//!    `pvfs.tls.…`);
//! 3. the error's own text (the record's `error` or `reason` field), matched
//!    against the phrases Rust, rustls, SQLite and PVFS's errors print;
//! 4. otherwise `other`.

use crate::{Field, Value};

/// The classes, in the order the docs list them.
pub const CLASSES: &[&str] =
    &["network", "disk", "auth", "protocol", "data", "slow", "config", "internal", "external", "other"];

/// The field the kind travels in.
pub const FIELD: &str = "error_kind";

/// `class` or `class:detail`, the class one of [`CLASSES`] and the detail
/// lowercase words joined by `_`.
pub fn valid(kind: &str) -> bool {
    let (class, detail) = match kind.split_once(':') {
        Some((c, d)) => (c, Some(d)),
        None => (kind, None),
    };
    CLASSES.contains(&class)
        && detail.is_none_or(|d| {
            !d.is_empty()
                && d.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && d.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// Rule 2: the event names whose kind is in the name.
pub fn from_event(event: &str) -> Option<&'static str> {
    if event.ends_with(".panicked") {
        Some("internal:panic")
    } else if event.ends_with("_slow") || event.ends_with(".slow") {
        Some("slow:held")
    } else if event.contains(".tls.") {
        Some("network:tls")
    } else {
        None
    }
}

/// Rule 3, in order: the more specific phrase before the general one
/// ("closed during handshake" is a dropped connection, not TLS; "I/O error
/// during …: No space left" is a full disk, not a generic I/O error).
const TEXT_RULES: &[(&[&str], &str)] = &[
    (&["no space left", "disk full", "quota exceeded"], "disk:no_space"),
    (&["read-only file system"], "disk:read_only"),
    (&["connection refused"], "network:refused"),
    (&["timed out", "timeout", "resource temporarily unavailable", "would block"], "network:timeout"),
    (
        &[
            "connection reset",
            "broken pipe",
            "unexpected eof",
            "failed to fill whole buffer",
            "connection closed",
            "closed before",
            "closed during",
            "connection aborted",
        ],
        "network:dropped",
    ),
    (
        &[
            "no route to host",
            "network is unreachable",
            "host is down",
            "name or service not known",
            "failed to lookup address",
            "temporary failure in name resolution",
        ],
        "network:unreachable",
    ),
    (&["certificate", "tls", "handshake", "received fatal alert", "peer is incompatible"], "network:tls"),
    (&["address already in use", "address in use"], "config:address_in_use"),
    (&["too many open files"], "config:limits"),
    (&["transport endpoint is not connected"], "disk:not_connected"),
    (&["device or resource busy"], "disk:busy"),
    (&["sqlite is busy", "database is locked", "busy/locked"], "slow:busy"),
    (&["database disk image is malformed", "corruption in"], "data:corruption"),
    (&["database error", "sqlite"], "disk:database"),
    (&["integrity violation", "integrity", "hash mismatch", "checksum"], "data:integrity"),
    (&["log chain broken", "diverged", "differs from"], "data:diverged"),
    (&["fenced"], "data:fenced"),
    (&["canonical-encoding"], "data:encoding"),
    (&["permission denied", "operation not permitted"], "disk:permission"),
    (&["revoked"], "auth:revoked"),
    (&["bad signature", "signature"], "auth:signature"),
    (&["forbidden", "not a member", "unauthorized", "access denied", "not allowed"], "auth:forbidden"),
    (&["unknown op", "unknown_op"], "protocol:unknown_op"),
    (&["protocol", "unexpected"], "protocol:unexpected"),
    (&["malformed", "not hex", "expected value", "invalid json", "invalid type"], "protocol:malformed"),
    (&["invalid input"], "config:invalid"),
    (&["region_not_held", "not held"], "data:not_held"),
    (&["no such file", "does not exist"], "disk:not_found"),
    (&["not found", "not_found"], "data:not_found"),
    (&["input/output error", "i/o error"], "disk:io"),
    (&["io: "], "network:io"),
    (&["ffprobe", "fusermount", "exit status", "exited with"], "external:tool"),
];

/// Rule 3 on one text.
pub fn from_text(text: &str) -> Option<&'static str> {
    let t = text.to_ascii_lowercase();
    TEXT_RULES.iter().find(|(needles, _)| needles.iter().any(|n| t.contains(n))).map(|(_, k)| *k)
}

/// The kind for a record with these fields: the site's own, else rules 2–4.
pub fn classify(event: &str, fields: &[Field]) -> String {
    if let Some(Value::Str(k)) = fields.iter().find(|f| f.name == FIELD).map(|f| &f.value) {
        return k.clone();
    }
    if let Some(k) = from_event(event) {
        return k.to_string();
    }
    for name in ["error", "reason"] {
        if let Some(f) = fields.iter().find(|f| f.name == name) {
            if let Some(k) = from_text(&f.value.to_string()) {
                return k.to_string();
            }
        }
    }
    "other".to_string()
}
