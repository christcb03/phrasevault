//! Signature audit log (doc 14 §4, §9 phase 5): an append-only JSONL file of
//! every signing decision the agent makes — approved or not — plus lock events.
//! One line per event, `0600`, no key material (only the digest, which is
//! public anyway once the event is committed).
//!
//! Best-effort by design: the log is for the owner's forensics, not a second
//! authorization gate, so a write failure warns on stderr and never blocks a
//! signature the policy already approved.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// One audit line.
#[derive(Serialize)]
pub struct AuditEntry<'a> {
    /// Milliseconds since the epoch.
    pub ts_ms: u64,
    /// `"sign"`, `"lock"`, `"idle_lock"`, `"unlock"`, or `"serve_start"`.
    pub event: &'a str,
    /// The signing request type, when `event` is `"sign"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<&'a str>,
    /// `"approved"`, `"denied"`, `"rate_limited"`, `"locked"`, or `"error"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<&'a str>,
    /// The 32-byte digest that was (or would have been) signed, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<&'a str>,
}

/// An open audit log; appends are serialized and flushed per line.
pub struct AuditLog {
    path: PathBuf,
    file: Mutex<File>,
}

impl AuditLog {
    /// Open (or create, mode `0600`) the log at `path`.
    pub fn open(path: &Path) -> std::io::Result<AuditLog> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(AuditLog {
            path: path.to_path_buf(),
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one entry. Best-effort: failures warn on stderr, never propagate.
    pub fn record(&self, entry: &AuditEntry<'_>) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let entry = AuditEntry { ts_ms: ts, ..*entry };
        let Ok(line) = serde_json::to_string(&entry) else {
            return;
        };
        let mut f = self.file.lock().expect("audit log poisoned");
        if writeln!(f, "{line}").and_then(|_| f.flush()).is_err() {
            eprintln!(
                "pvfs-companion: WARNING: could not append to the audit log at {}",
                self.path.display()
            );
        }
    }

    /// Convenience for the common case.
    pub fn sign(&self, request_type: &str, origin: &str, decision: &str, digest: &str) {
        self.record(&AuditEntry {
            ts_ms: 0,
            event: "sign",
            request_type: Some(request_type),
            origin: Some(origin),
            decision: Some(decision),
            digest: Some(digest),
        });
    }

    /// A bare lifecycle event (`serve_start`, `lock`, `idle_lock`, `unlock`).
    pub fn event(&self, event: &str) {
        self.record(&AuditEntry {
            ts_ms: 0,
            event,
            request_type: None,
            origin: None,
            decision: None,
            digest: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_jsonl_lines_with_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        log.event("serve_start");
        log.sign("root_device_cert", "local", "approved", "aa".repeat(32).as_str());
        log.sign("identity_tag", "web", "denied", &"bb".repeat(32));
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for l in &lines {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert!(v["ts_ms"].as_u64().unwrap() > 0);
        }
        assert!(lines[1].contains("\"decision\":\"approved\""));
        assert!(lines[2].contains("\"decision\":\"denied\""));
    }

    #[cfg(unix)]
    #[test]
    fn audit_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        log.event("serve_start");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
