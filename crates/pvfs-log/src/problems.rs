//! PVOS D230 — a process's failures, structured, in a small file of their
//! own: every record at warning or above, as one schema-1 JSON line.
//!
//! The box's own log already has them, but not always in a shape that can
//! be filtered by time and level there: the NAS's `pvfsd.log` and the Mac
//! companion's `companion.log` are plain text. This file is what `pvfs
//! diagnose` (through pvfsd's `Diagnose`) and `pvfs-companion diagnose`
//! read back. pvfsd and its mounts share `<data dir>/log-problems.jsonl`;
//! the companion writes `~/Library/Logs/PVFS/companion-problems.jsonl`.
//!
//! It is rendered at the process's local privacy, as the box's own log is,
//! and capped at [`CAP_BYTES`]: past that it becomes `.1` (one old copy).
//! Writing it never fails a record and never logs.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::{Record, Severity};

/// pvfsd's and its mounts' file, in their data dir.
pub const FILE_NAME: &str = "log-problems.jsonl";

/// The file's size before it is set aside as `.1`.
pub const CAP_BYTES: u64 = 1024 * 1024;

static FILE: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Keep this process's failures in `path` from now on (its directory is
/// made if it is missing).
pub fn open(path: PathBuf) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    *FILE.lock().unwrap_or_else(|p| p.into_inner()) = Some(path);
}

/// The file this process writes, if it keeps one.
pub fn path() -> Option<PathBuf> {
    FILE.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

/// The set-aside copy: `log-problems.jsonl` → `log-problems.jsonl.1`.
pub fn older(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".1");
    PathBuf::from(s)
}

/// A record at warning or above, to the file (called for every record).
pub(crate) fn offer(rec: &Record) {
    if rec.severity > Severity::Warning {
        return;
    }
    let Some(p) = path() else { return };
    let lg = crate::logger();
    let view = crate::render(rec, lg.cfg.privacy, lg.cfg.pseudonym_key.as_ref());
    let mut line = crate::to_json(rec, &view);
    line.push('\n');
    append(&p, &line);
}

fn append(p: &Path, line: &str) {
    if std::fs::metadata(p).is_ok_and(|m| m.len() + line.len() as u64 > CAP_BYTES) {
        let _ = std::fs::rename(p, older(p));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(p) {
        // One write, so processes sharing the file do not interleave a line.
        let _ = f.write_all(line.as_bytes());
    }
}

/// The records in `path` (and its `.1`) made at or after `since_ms`, oldest
/// first, at most `max` of them (the newest), and how many older ones were
/// left out. A line that does not parse (a torn last line) is skipped.
pub fn read_since(path: &Path, since_ms: u64, max: usize) -> (Vec<Record>, u64) {
    let mut out = Vec::new();
    for p in [older(path), path.to_path_buf()] {
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        out.extend(text.lines().filter_map(crate::parse_json).filter(|r| r.ts_ms >= since_ms));
    }
    out.sort_by_key(|r| (r.ts_ms, r.seq));
    let dropped = out.len().saturating_sub(max);
    (out.split_off(dropped), dropped as u64)
}
