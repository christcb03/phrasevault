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
pub const JOB_NAMES: [&str; 5] = ["follow", "sync", "export", "tier", "evict"];

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

#[cfg(test)]
mod tests {
    use super::*;

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
