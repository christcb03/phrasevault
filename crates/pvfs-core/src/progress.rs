//! PVOS D207 — a running pass's own account of itself.
//!
//! The stall check judged passes by how long they took: a pass in flight
//! past three times the job's last one was `stalled`, and a job with no
//! completed pass for a while was `overdue`. Neither could tell a healthy
//! 26-hour first pass from a wedged one, so `overdue` was filtered out
//! everywhere — and a real stall with it. A pass that says how far it has
//! got is judged by whether it is still getting anywhere.
//!
//! One [`JobProgress`] per job that reports, kept by the runner for the
//! job's life and shared with each pass. Every call takes a small lock for
//! a few field updates — never across work, and never the database writer.

use std::sync::Mutex;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A file a pass has in hand, as [`JobProgress::snapshot`] reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileProgress {
    pub path: String,
    pub hash: Option<String>,
    pub bytes: u64,
    pub size: Option<u64>,
    pub advanced_ms: u64,
}

/// A pass in flight, as [`JobProgress::snapshot`] reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassProgress {
    pub started_ms: u64,
    pub advanced_ms: u64,
    pub files_done: u64,
    pub bytes_done: u64,
    pub phase: Option<String>,
    pub current: Vec<FileProgress>,
}

struct InHand {
    token: u64,
    file: FileProgress,
}

struct Pass {
    p: PassProgress,
    in_hand: Vec<InHand>,
    next_token: u64,
}

/// One job's progress: a pass in flight, or none.
#[derive(Default)]
pub struct JobProgress {
    pass: Mutex<Option<Pass>>,
}

/// What [`JobProgress::begin_file`] hands back, for that file's later calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileToken(u64);

impl JobProgress {
    pub fn new() -> JobProgress {
        JobProgress::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut Pass, u64) -> R) -> Option<R> {
        let mut g = self.pass.lock().unwrap_or_else(|p| p.into_inner());
        let now = now_ms();
        g.as_mut().map(|pass| {
            pass.p.advanced_ms = now;
            f(pass, now)
        })
    }

    /// A pass has begun: everything counted from zero, now.
    pub fn begin_pass(&self) {
        let now = now_ms();
        *self.pass.lock().unwrap_or_else(|p| p.into_inner()) = Some(Pass {
            p: PassProgress { started_ms: now, advanced_ms: now, ..Default::default() },
            in_hand: Vec::new(),
            next_token: 0,
        });
    }

    /// The pass has ended (completed, stopped or failed): none in flight.
    pub fn end_pass(&self) {
        *self.pass.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    /// Is a pass in flight?
    pub fn in_pass(&self) -> bool {
        self.pass.lock().unwrap_or_else(|p| p.into_inner()).is_some()
    }

    /// What the pass is doing now (`walking`, `hashing`, …). Moves it.
    pub fn phase(&self, phase: &str) {
        self.with(|pass, _| {
            if pass.p.phase.as_deref() != Some(phase) {
                pass.p.phase = Some(phase.to_string());
            }
        });
    }

    /// Progress with no file to name: a folder walked, a step written.
    pub fn tick(&self) {
        self.with(|_, _| ());
    }

    /// A file taken in hand: `have` bytes of it are already done (a resumed
    /// partial). Outside a pass the token is still good, and counts nothing.
    pub fn begin_file(&self, path: &str, hash: Option<&str>, size: Option<u64>, have: u64) -> FileToken {
        self.with(|pass, now| {
            let token = pass.next_token;
            pass.next_token += 1;
            pass.in_hand.push(InHand {
                token,
                file: FileProgress {
                    path: path.to_string(),
                    hash: hash.map(str::to_string),
                    bytes: have,
                    size,
                    advanced_ms: now,
                },
            });
            FileToken(token)
        })
        .unwrap_or(FileToken(u64::MAX))
    }

    /// A file in hand already has `have` bytes (a partial an earlier pass
    /// left): its own count, not this pass's work.
    pub fn file_have(&self, t: FileToken, have: u64) {
        self.with(|pass, now| {
            if let Some(h) = pass.in_hand.iter_mut().find(|h| h.token == t.0) {
                h.file.bytes = have;
                h.file.advanced_ms = now;
            }
        });
    }

    /// `n` more bytes of a file in hand are done.
    pub fn file_bytes(&self, t: FileToken, n: u64) {
        self.with(|pass, now| {
            pass.p.bytes_done += n;
            if let Some(h) = pass.in_hand.iter_mut().find(|h| h.token == t.0) {
                h.file.bytes += n;
                h.file.advanced_ms = now;
            }
        });
    }

    /// A file put down: counted as done when `done` (its bytes were counted
    /// as they went), else simply no longer in hand (stopped, failed).
    pub fn end_file(&self, t: FileToken, done: bool) {
        self.with(|pass, _| {
            pass.in_hand.retain(|h| h.token != t.0);
            if done {
                pass.p.files_done += 1;
            }
        });
    }

    /// A file done without being read (its hash from a row or a sidecar):
    /// one more file, and its bytes.
    pub fn file_done(&self, bytes: u64) {
        self.with(|pass, _| {
            pass.p.files_done += 1;
            pass.p.bytes_done += bytes;
        });
    }

    /// The pass in flight, if any.
    pub fn snapshot(&self) -> Option<PassProgress> {
        let g = self.pass.lock().unwrap_or_else(|p| p.into_inner());
        g.as_ref().map(|pass| PassProgress {
            current: pass.in_hand.iter().map(|h| h.file.clone()).collect(),
            ..pass.p.clone()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_counts_files_and_bytes_and_ends_clear() {
        let p = JobProgress::new();
        assert!(p.snapshot().is_none(), "no pass, no account");
        // Outside a pass, nothing counts and nothing panics.
        let t = p.begin_file("x", None, None, 0);
        p.file_bytes(t, 5);
        p.end_file(t, true);
        assert!(p.snapshot().is_none());

        p.begin_pass();
        let s = p.snapshot().unwrap();
        assert_eq!((s.files_done, s.bytes_done, s.current.len()), (0, 0, 0));
        assert_eq!(s.started_ms, s.advanced_ms);
        p.phase("hashing");
        let a = p.begin_file("Show/e01.mkv", Some("abc"), Some(100), 40);
        let b = p.begin_file("Show/e02.mkv", None, Some(50), 0);
        p.file_bytes(a, 30);
        p.file_bytes(b, 10);
        let s = p.snapshot().unwrap();
        assert_eq!(s.phase.as_deref(), Some("hashing"));
        assert_eq!(s.bytes_done, 40, "bytes done this pass; a resumed partial's own bytes are not");
        assert_eq!(s.current.len(), 2);
        assert_eq!(s.current[0].bytes, 70, "a file's bytes include what it resumed from");
        assert_eq!(s.current[0].hash.as_deref(), Some("abc"));
        p.end_file(a, true);
        p.end_file(b, false);
        p.file_done(1_000);
        let s = p.snapshot().unwrap();
        assert_eq!((s.files_done, s.bytes_done), (2, 1_040));
        assert!(s.current.is_empty(), "a file put down leaves `current`");
        p.end_pass();
        assert!(p.snapshot().is_none());
        assert!(!p.in_pass());
    }

    #[test]
    fn every_call_moves_the_pass() {
        let p = JobProgress::new();
        p.begin_pass();
        let first = p.snapshot().unwrap().advanced_ms;
        std::thread::sleep(std::time::Duration::from_millis(5));
        p.tick();
        assert!(p.snapshot().unwrap().advanced_ms > first);
        // A new pass starts from zero.
        p.file_done(9);
        p.begin_pass();
        assert_eq!(p.snapshot().unwrap().files_done, 0);
    }
}
