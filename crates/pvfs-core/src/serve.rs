//! P5 — serve-job configuration (doc 18 §2): which background jobs this
//! instance's daemon runs for the forest. Deployment state, **never** log
//! events — the same rule as placement (doc 17 §6): what a box does for
//! itself needs no owner signature, and two boxes legitimately differ.
//!
//! The file is `<data_dir>/serve.jobs`, one enabled job per line. The daemon
//! reads it at start and on SIGHUP; `pvfs serve enable|disable|ls` edits it.
//! Job *bodies* live in `pvfsd` — this module only answers "which jobs is
//! this data dir configured to run".

use std::path::{Path, PathBuf};

use crate::engine::bad;
use crate::error::{PvfsError, Result};

const JOBS_FILE: &str = "serve.jobs";
const JOBS_HEADER: &str = "pvfs-serve-jobs 1";

/// Every job the daemon knows how to run (doc 18 §1's table, in the order
/// they appear there). An unknown name in the file is a hard error — a typo
/// silently running zero jobs is exactly the failure mode we refuse.
pub const JOB_NAMES: [&str; 6] = ["follow", "watch", "sync", "export", "tier", "evict"];

pub fn jobs_path(data_dir: &Path) -> PathBuf {
    data_dir.join(JOBS_FILE)
}

fn check_name(job: &str) -> Result<()> {
    if JOB_NAMES.contains(&job) {
        Ok(())
    } else {
        Err(bad(
            "serve",
            &format!("unknown job {job:?} — one of: {}", JOB_NAMES.join(", ")),
        ))
    }
}

/// Jobs enabled for this data dir, file order preserved. A missing file means
/// none — a daemon with no `serve.jobs` runs exactly as it did before P5.
pub fn load_jobs(data_dir: &Path) -> Result<Vec<String>> {
    let text = match std::fs::read_to_string(jobs_path(data_dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PvfsError::io("read serve.jobs", e)),
    };
    let mut lines = text.lines();
    if lines.next() != Some(JOBS_HEADER) {
        return Err(bad("serve", "unrecognized serve.jobs file"));
    }
    let mut out = Vec::new();
    for line in lines.map(str::trim).filter(|l| !l.is_empty()) {
        check_name(line)?;
        if !out.iter().any(|j| j == line) {
            out.push(line.to_string());
        }
    }
    Ok(out)
}

fn save_jobs(data_dir: &Path, jobs: &[String]) -> Result<()> {
    let mut text = String::from(JOBS_HEADER);
    text.push('\n');
    for j in jobs {
        text.push_str(j);
        text.push('\n');
    }
    crate::storage::atomic_overwrite(&jobs_path(data_dir), text.as_bytes())
}

/// Enable or disable one job. Returns whether the file changed (enabling an
/// enabled job, or disabling a disabled one, is an idempotent no-op).
pub fn set_job(data_dir: &Path, job: &str, enabled: bool) -> Result<bool> {
    check_name(job)?;
    let mut jobs = load_jobs(data_dir)?;
    let present = jobs.iter().any(|j| j == job);
    match (present, enabled) {
        (false, true) => jobs.push(job.to_string()),
        (true, false) => jobs.retain(|j| j != job),
        _ => return Ok(false),
    }
    save_jobs(data_dir, &jobs)?;
    Ok(true)
}

// ---- kept-fresh exports (the export job's work list, doc 18 §5 P5.2) --------

const EXPORTS_FILE: &str = "serve.exports";
const EXPORTS_HEADER: &str = "pvfs-serve-exports 1";

/// One export the daemon keeps fresh: re-run `export` for `node` into `dest`
/// whenever content changes. Recorded by `pvfs export --keep-fresh` — the
/// entry captures exactly the flags that run was invoked with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    pub node: String,
    pub mode: String,
    pub fetch: bool,
    pub prune: bool,
    pub dest: std::path::PathBuf,
}

pub fn exports_path(data_dir: &Path) -> PathBuf {
    data_dir.join(EXPORTS_FILE)
}

/// Kept-fresh exports, file order. Missing file = none.
pub fn load_exports(data_dir: &Path) -> Result<Vec<ExportEntry>> {
    let text = match std::fs::read_to_string(exports_path(data_dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PvfsError::io("read serve.exports", e)),
    };
    let mut lines = text.lines();
    if lines.next() != Some(EXPORTS_HEADER) {
        return Err(bad("serve", "unrecognized serve.exports file"));
    }
    let mut out = Vec::new();
    for line in lines.filter(|l| !l.trim().is_empty()) {
        // "<node> <mode> <fetch 0|1> <prune 0|1> <dest…>" — dest may hold spaces
        let mut parts = line.splitn(5, ' ');
        match (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) {
            (Some(node), Some(mode), Some(fetch), Some(prune), Some(dest))
                if !dest.is_empty() =>
            {
                out.push(ExportEntry {
                    node: node.to_string(),
                    mode: mode.to_string(),
                    fetch: fetch == "1",
                    prune: prune == "1",
                    dest: std::path::PathBuf::from(dest),
                });
            }
            _ => return Err(bad("serve", &format!("corrupt serve.exports line: {line:?}"))),
        }
    }
    Ok(out)
}

fn save_exports(data_dir: &Path, entries: &[ExportEntry]) -> Result<()> {
    let mut text = String::from(EXPORTS_HEADER);
    text.push('\n');
    for e in entries {
        text.push_str(&format!(
            "{} {} {} {} {}\n",
            e.node,
            e.mode,
            u8::from(e.fetch),
            u8::from(e.prune),
            e.dest.display()
        ));
    }
    crate::storage::atomic_overwrite(&exports_path(data_dir), text.as_bytes())
}

/// Record (or update — same node+dest replaces) a kept-fresh export.
pub fn upsert_export(data_dir: &Path, entry: ExportEntry) -> Result<()> {
    let mut entries = load_exports(data_dir)?;
    entries.retain(|e| !(e.node == entry.node && e.dest == entry.dest));
    entries.push(entry);
    save_exports(data_dir, &entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_round_trip_and_upsert() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_exports(dir.path()).unwrap().is_empty());
        let e = ExportEntry {
            node: "a".repeat(64),
            mode: "symlink".into(),
            fetch: true,
            prune: true,
            dest: std::path::PathBuf::from("/srv/plex library"), // space kept
        };
        upsert_export(dir.path(), e.clone()).unwrap();
        assert_eq!(load_exports(dir.path()).unwrap(), vec![e.clone()]);
        // same node+dest replaces rather than duplicates
        let e2 = ExportEntry {
            mode: "copy".into(),
            ..e.clone()
        };
        upsert_export(dir.path(), e2.clone()).unwrap();
        assert_eq!(load_exports(dir.path()).unwrap(), vec![e2]);
        // corrupt file refuses
        std::fs::write(exports_path(dir.path()), "wrong\n").unwrap();
        assert!(load_exports(dir.path()).is_err());
    }

    #[test]
    fn missing_file_means_no_jobs() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_jobs(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn enable_disable_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(set_job(dir.path(), "sync", true).unwrap());
        assert!(set_job(dir.path(), "evict", true).unwrap());
        assert_eq!(load_jobs(dir.path()).unwrap(), ["sync", "evict"]);
        // idempotent enable — no change, no duplicate
        assert!(!set_job(dir.path(), "sync", true).unwrap());
        assert_eq!(load_jobs(dir.path()).unwrap(), ["sync", "evict"]);
        assert!(set_job(dir.path(), "sync", false).unwrap());
        assert_eq!(load_jobs(dir.path()).unwrap(), ["evict"]);
        assert!(!set_job(dir.path(), "sync", false).unwrap());
    }

    #[test]
    fn unknown_job_is_refused_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        assert!(set_job(dir.path(), "defrag", true).is_err());
        std::fs::write(
            jobs_path(dir.path()),
            "pvfs-serve-jobs 1\nfollow\ndefrag\n",
        )
        .unwrap();
        assert!(load_jobs(dir.path()).is_err());
    }

    #[test]
    fn unrecognized_header_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(jobs_path(dir.path()), "something-else\nfollow\n").unwrap();
        assert!(load_jobs(dir.path()).is_err());
    }
}
