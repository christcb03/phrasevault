//! PVOS D229 — the log level, changed while a process runs.
//!
//! `PVFS_LOG_LEVEL` is read once at start, so debugging a live box used to
//! mean editing its unit and restarting it — which clears the state being
//! looked at. Now a daemon writes `<data dir>/log-level.json` (`pvfs serve
//! log-level`), and every process of that data dir (pvfsd, each mount)
//! checks it every [`POLL`] through [`watch`]:
//!
//! ```json
//! {"level": "debug", "until_ms": 1760050000000, "by": "key:4f1c…"}
//! ```
//!
//! It never lasts past `until_ms` (at most [`MAX_MINUTES`]): a forgotten
//! debug cannot fill a disk or a log server. A restart inside the window
//! keeps it, which is wanted — "debug for 30 minutes, then restart" shows
//! the start in debug. Each change, and the return to the configured level,
//! is a `pvfs.log.level_changed` record (audit).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{actor, Severity};

/// The file's name in a data dir.
pub const FILE: &str = "log-level.json";
/// How often a process checks the file.
pub const POLL: Duration = Duration::from_secs(5);
/// What `pvfs serve log-level` offers first.
pub const DEFAULT_MINUTES: u32 = 60;
/// The longest a level may last: a day.
pub const MAX_MINUTES: u32 = 24 * 60;
/// The levels a person may set (the rest are for records, not filters).
pub const SETTABLE: &[&str] = &["error", "warning", "notice", "info", "debug"];

const NONE: u8 = u8::MAX;
static OVERRIDE: AtomicU8 = AtomicU8::new(NONE);
static UNTIL_MS: AtomicU64 = AtomicU64::new(0);

fn from_u8(v: u8) -> Option<Severity> {
    Some(match v {
        0 => Severity::Emergency,
        1 => Severity::Alert,
        2 => Severity::Critical,
        3 => Severity::Error,
        4 => Severity::Warning,
        5 => Severity::Notice,
        6 => Severity::Info,
        7 => Severity::Debug,
        _ => return None,
    })
}

/// The override in force, if any and if its time has not run out.
pub(crate) fn active() -> Option<Severity> {
    let v = OVERRIDE.load(Ordering::Relaxed);
    if v == NONE || crate::time::now_ms() >= UNTIL_MS.load(Ordering::Relaxed) {
        return None;
    }
    from_u8(v)
}

/// Use `level` until `until_ms` (Unix ms) instead of the configured level.
pub fn set_override(level: Severity, until_ms: u64) {
    UNTIL_MS.store(until_ms, Ordering::Relaxed);
    OVERRIDE.store(level as u8, Ordering::Relaxed);
}

/// Back to the configured level now.
pub fn clear_override() {
    OVERRIDE.store(NONE, Ordering::Relaxed);
}

/// The override in force and when it ends, for `serve status`.
pub fn override_until() -> Option<(Severity, u64)> {
    active().map(|s| (s, UNTIL_MS.load(Ordering::Relaxed)))
}

/// One of [`SETTABLE`], by name or its short form.
pub fn parse_settable(s: &str) -> Option<Severity> {
    let sev = Severity::parse(s)?;
    SETTABLE.contains(&sev.as_str()).then_some(sev)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LevelFile {
    pub level: String,
    pub until_ms: u64,
    /// Who set it (`key:<hex>`), for the audit record.
    #[serde(default)]
    pub by: String,
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE)
}

/// Write the file — `level` for `minutes` (clamped to 1…[`MAX_MINUTES`])
/// from `now_ms` — or, with `None`, remove it (back to the configured level).
/// Written beside and renamed over, so a reader never sees half a file.
pub fn write(data_dir: &Path, level: Option<Severity>, minutes: u32, by: &str, now_ms: u64) -> std::io::Result<Option<LevelFile>> {
    let p = path(data_dir);
    let Some(level) = level else {
        match std::fs::remove_file(&p) {
            Ok(()) => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
    };
    let minutes = minutes.clamp(1, MAX_MINUTES);
    let f = LevelFile { level: level.as_str().to_string(), until_ms: now_ms + u64::from(minutes) * 60_000, by: by.to_string() };
    let tmp = data_dir.join(format!(".{FILE}.tmp-{}", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec(&f).map_err(std::io::Error::other)?)?;
    std::fs::rename(&tmp, &p)?;
    Ok(Some(f))
}

/// The file as it is: `Ok(None)` when there is none.
pub fn read(data_dir: &Path) -> Result<Option<LevelFile>, String> {
    match std::fs::read(path(data_dir)) {
        Ok(b) => serde_json::from_slice::<LevelFile>(&b).map(Some).map_err(|e| format!("{FILE}: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{FILE}: {e}")),
    }
}

/// What a process last applied from its file, so each change is logged once.
#[derive(Default)]
pub struct Watcher {
    applied: Option<(Severity, u64, String)>,
    problem: Option<String>,
}

impl Watcher {
    pub fn new() -> Watcher {
        Watcher::default()
    }

    /// Read the file and apply what it asks for now. Returns true when the
    /// level changed. A file that cannot be read is named once (until it
    /// changes) and changes nothing.
    pub fn apply(&mut self, data_dir: &Path, now_ms: u64) -> bool {
        let wanted = match read(data_dir) {
            Ok(Some(f)) => match parse_settable(&f.level) {
                Some(sev) if f.until_ms > now_ms => {
                    self.problem = None;
                    Some((sev, f.until_ms, f.by))
                }
                Some(_) => {
                    self.problem = None;
                    None
                }
                None => {
                    self.name_problem(format!("{FILE}: level {:?} is not one of {}", f.level, SETTABLE.join("|")));
                    return false;
                }
            },
            Ok(None) => {
                self.problem = None;
                None
            }
            Err(e) => {
                self.name_problem(e);
                return false;
            }
        };
        if wanted == self.applied {
            return false;
        }
        let service = crate::logger().cfg.service.clone();
        let configured = crate::configured_level();
        let previous = crate::current_level();
        match &wanted {
            Some((sev, until, by)) => {
                // More detail: apply first, so the record itself is kept at
                // any level. Less: log first, while it still shows.
                let louder = *sev > previous;
                if louder {
                    set_override(*sev, *until);
                }
                let at = crate::time::format_ts(*until);
                crate::pv_notice!(audit "pvfs.log.level_changed", level = sev.as_str(), previous = previous.as_str(),
                    until_ms = *until, by = actor(by), reason = "set";
                    "{service}: log level {} until {at} (was {}; configured {})", sev.as_str(), previous.as_str(), configured.as_str());
                if !louder {
                    set_override(*sev, *until);
                }
            }
            None => {
                let reason = if self.applied.as_ref().is_some_and(|(_, until, _)| *until <= now_ms) { "expired" } else { "cleared" };
                crate::pv_notice!(audit "pvfs.log.level_changed", level = configured.as_str(), previous = previous.as_str(),
                    reason = reason;
                    "{service}: log level back to {} ({reason}; was {})", configured.as_str(), previous.as_str());
                clear_override();
            }
        }
        self.applied = wanted;
        true
    }

    fn name_problem(&mut self, p: String) {
        if self.problem.as_deref() != Some(p.as_str()) {
            let service = crate::logger().cfg.service.clone();
            crate::pv_warn!("pvfs.log.level_file_unreadable", error = crate::content(&p), error_kind = "config:level_file";
                "{service}: the live log level file is ignored: {p}");
            self.problem = Some(p);
        }
    }
}

/// The process's watcher and the data dir it reads, shared by [`watch`]'s
/// thread and [`apply_now`] (a daemon applying the file it just wrote), so a
/// change is logged once however it is noticed.
static WATCHER: Mutex<Option<(PathBuf, Watcher)>> = Mutex::new(None);
static WATCHING: Mutex<bool> = Mutex::new(false);

/// Apply `<data_dir>/log-level.json` now. The first call names the data dir
/// for this process; later calls apply that one's file.
pub fn apply_now(data_dir: &Path) -> bool {
    let mut g = WATCHER.lock().unwrap_or_else(|p| p.into_inner());
    let (dir, w) = g.get_or_insert_with(|| (data_dir.to_path_buf(), Watcher::new()));
    w.apply(dir, crate::time::now_ms())
}

/// Apply `<data_dir>/log-level.json` now (so a restart inside its window
/// logs its start at that level), then every [`POLL`] on a thread of its
/// own. Once per process; a second call does nothing.
pub fn watch(data_dir: PathBuf) {
    {
        let mut started = WATCHING.lock().unwrap_or_else(|p| p.into_inner());
        if *started {
            return;
        }
        *started = true;
    }
    apply_now(&data_dir);
    let _ = std::thread::Builder::new().name("pvfs-log-level".into()).spawn(move || loop {
        std::thread::sleep(POLL);
        apply_now(&data_dir);
    });
}
