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

use crate::proto::ApprovalContext;

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
    /// The broker-built approval context, when the request carried one (doc 16
    /// §3.2: the audit records the full context — it is all public metadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<&'a ApprovalContext>,
}

/// PVOS D222b decision 6 — every audit entry is also a log record
/// (`pvfs.agent.audit`, category audit), so it reaches a log server like the
/// daemons' lines. The file is unchanged: the Mac app's Console reads it.
/// A decision other than `approved` is the failure outcome.
fn log_entry(e: &AuditEntry<'_>) {
    use pvfs_log::{content, net, pv_notice, pv_warn};
    let action = e.event;
    let decision = e.decision.unwrap_or("");
    let request = e.request_type.unwrap_or("");
    let origin = e.origin.unwrap_or("");
    let digest = e.digest.unwrap_or("");
    let summary = e.context.map(|c| c.summary.clone()).unwrap_or_default();
    let what = if request.is_empty() { action.to_string() } else { format!("{action} {request}") };
    let from = if origin.is_empty() { String::new() } else { format!(" from {origin}") };
    let on = if decision.is_empty() { String::new() } else { format!(": {decision}") };
    if decision.is_empty() || decision == "approved" {
        pv_notice!(audit success "pvfs.agent.audit", action = action, decision = decision, request_type = request,
            origin = net(origin), digest = digest, summary = content(&summary);
            "pvfs-companion: audit: {what}{from}{on}");
    } else {
        pv_warn!(audit failure "pvfs.agent.audit", action = action, decision = decision, request_type = request,
            origin = net(origin), digest = digest, summary = content(&summary), error_kind = "auth:denied";
            "pvfs-companion: audit: {what}{from}{on}");
    }
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
        log_entry(&entry);
        let mut f = self.file.lock().expect("audit log poisoned");
        if writeln!(f, "{line}").and_then(|_| f.flush()).is_err() {
            pvfs_log::pv_error!("pvfs.companion.audit_unwritten", path = pvfs_log::content(self.path.display()), error_kind = "disk:io";
                "pvfs-companion: WARNING: could not append to the audit log at {}",
                self.path.display()
            );
        }
    }

    /// Convenience for the common case.
    pub fn sign(&self, request_type: &str, origin: &str, decision: &str, digest: &str) {
        self.sign_ctx(request_type, origin, decision, digest, None);
    }

    /// As [`sign`](AuditLog::sign), recording the approval context when present.
    pub fn sign_ctx(
        &self,
        request_type: &str,
        origin: &str,
        decision: &str,
        digest: &str,
        context: Option<&ApprovalContext>,
    ) {
        self.record(&AuditEntry {
            ts_ms: 0,
            event: "sign",
            request_type: Some(request_type),
            origin: Some(origin),
            decision: Some(decision),
            digest: Some(digest),
            context,
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
            context: None,
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

    /// PVOS D228 (D222b Deviation 6) — each entry is also a record:
    /// `pvfs.agent.audit`, category audit; approved is success, anything
    /// else failure; the origin is a network field (gone at `minimal` unless
    /// security/audit keeps it), the summary content.
    #[test]
    fn each_entry_is_an_audit_record() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(&dir.path().join("audit.jsonl")).unwrap();
        let recs = pvfs_log::capture(|| {
            log.sign("identity_tag", "https://app.example", "approved", &"aa".repeat(32));
            log.sign("root_device_cert", "local", "denied", &"bb".repeat(32));
        });
        let audits: Vec<_> = recs.iter().filter(|r| r.event == "pvfs.agent.audit").collect();
        assert_eq!(audits.len(), 2, "{recs:?}");
        assert_eq!(audits[0].category, pvfs_log::Category::Audit);
        assert_eq!(audits[0].outcome, Some(pvfs_log::Outcome::Success));
        assert_eq!(audits[1].outcome, Some(pvfs_log::Outcome::Failure));
        assert_eq!(audits[1].severity, pvfs_log::Severity::Warning);
        let field = |r: &pvfs_log::Record, n: &str| r.fields.iter().find(|f| f.name == n).map(|f| (f.class, f.value.to_string()));
        assert_eq!(field(audits[0], "origin"), Some((pvfs_log::Class::Net, "https://app.example".into())));
        assert_eq!(field(audits[1], "decision"), Some((pvfs_log::Class::Meta, "denied".into())));
        assert!(audits[0].msg.contains("audit: sign identity_tag from https://app.example: approved"), "{}", audits[0].msg);
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
