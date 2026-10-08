//! journald's native protocol (D222 decision 6): today's line as `MESSAGE`,
//! the severity as `PRIORITY`, and the record's parts as `PV_*` fields, so
//! `journalctl PV_EVENT=pvfs.job.failed` works and a collector can lift them.
//!
//! Protocol: one datagram to `/run/systemd/journal/socket`; each field is
//! `NAME=value\n`, or — when the value holds a newline — `NAME\n`, the
//! value's length as a little-endian u64, the value, `\n`. Records over
//! 48 KiB are not sent this way (journald wants a memfd for big ones); the
//! caller falls back to `<N>line` on stderr.

use crate::{Record, View};

pub(crate) const MAX_DATAGRAM: usize = 48 * 1024;

/// The record's own `PV_*` names; a field with one of these names is sent as
/// `PV_F_<NAME>` so it cannot overwrite them.
const OWN: &[&str] = &["SCHEMA", "ID", "EVENT", "CATEGORY", "OUTCOME", "SERVICE", "COMPONENT", "VIA", "SEQ"];

/// journald field names: `[A-Z0-9_]`, not starting with `_` or a digit, at
/// most 64 characters.
pub(crate) fn field_name(name: &str) -> String {
    let mut up: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
        .collect();
    if OWN.contains(&up.as_str()) {
        up = format!("F_{up}");
    }
    let mut n = format!("PV_{up}");
    n.truncate(64);
    n
}

pub(crate) fn fields(rec: &Record, view: &View, ident: &str) -> Vec<(String, String)> {
    let mut f: Vec<(String, String)> = vec![
        ("MESSAGE".into(), view.line()),
        ("PRIORITY".into(), rec.severity.priority().to_string()),
        ("SYSLOG_IDENTIFIER".into(), ident.to_string()),
        ("PV_SCHEMA".into(), "1".into()),
        ("PV_ID".into(), rec.id.clone()),
        ("PV_EVENT".into(), rec.event.clone()),
        ("PV_CATEGORY".into(), rec.category.as_str().into()),
        ("PV_SERVICE".into(), rec.service.clone()),
    ];
    if let Some(o) = rec.outcome {
        f.push(("PV_OUTCOME".into(), o.as_str().into()));
    }
    if let Some(c) = &view.component {
        f.push(("PV_COMPONENT".into(), c.clone()));
    }
    if let Some(v) = &view.via {
        f.push(("PV_VIA".into(), v.clone()));
    }
    for fld in &view.fields {
        f.push((field_name(&fld.name), fld.value.to_string()));
    }
    f
}

pub(crate) fn datagram(fields: &[(String, String)]) -> Vec<u8> {
    let mut b = Vec::with_capacity(512);
    for (k, v) in fields {
        b.extend_from_slice(k.as_bytes());
        if v.contains('\n') {
            b.push(b'\n');
            b.extend_from_slice(&(v.len() as u64).to_le_bytes());
            b.extend_from_slice(v.as_bytes());
        } else {
            b.push(b'=');
            b.extend_from_slice(v.as_bytes());
        }
        b.push(b'\n');
    }
    b
}

#[cfg(target_os = "linux")]
mod sys {
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixDatagram;
    use std::sync::OnceLock;

    pub(crate) const SOCKET: &str = "/run/systemd/journal/socket";

    /// systemd sets `JOURNAL_STREAM=<dev>:<ino>` for a unit whose stderr is
    /// the journal. A child inherits the variable but not the stream (pvosd
    /// pipes its apps), so it must match stderr itself.
    pub(crate) fn stderr_is_journal() -> bool {
        let Ok(v) = std::env::var("JOURNAL_STREAM") else { return false };
        let Some((d, i)) = v.split_once(':') else { return false };
        let (Ok(d), Ok(i)) = (d.parse::<u64>(), i.parse::<u64>()) else { return false };
        let Ok(fd) = std::io::stderr().as_fd().try_clone_to_owned() else { return false };
        let Ok(md) = std::fs::File::from(fd).metadata() else { return false };
        md.dev() == d && md.ino() == i
    }

    pub(crate) fn send_to(buf: &[u8], path: &str) -> std::io::Result<()> {
        static SOCK: OnceLock<Option<UnixDatagram>> = OnceLock::new();
        let sock = SOCK.get_or_init(|| UnixDatagram::unbound().ok());
        match sock {
            Some(s) => s.send_to(buf, path).map(|_| ()),
            None => Err(std::io::Error::other("no datagram socket")),
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn stderr_is_journal() -> bool {
    sys::stderr_is_journal()
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn stderr_is_journal() -> bool {
    false
}

pub(crate) fn send(fields: &[(String, String)]) -> std::io::Result<()> {
    let buf = datagram(fields);
    if buf.len() > MAX_DATAGRAM {
        return Err(std::io::Error::other("record too big for one journal datagram"));
    }
    #[cfg(target_os = "linux")]
    {
        sys::send_to(&buf, sys::SOCKET)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(std::io::Error::other("no journal here"))
    }
}

/// For the real-journal test: send one record to journald now.
#[doc(hidden)]
pub fn __send_record(rec: &Record, ident: &str) -> std::io::Result<()> {
    let view = crate::render(rec, crate::Privacy::Full, None);
    send(&fields(rec, &view, ident))
}
