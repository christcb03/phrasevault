//! PVOS D199 — one writer per daemon.
//!
//! A pvfsd process writes `index.db` through ONE connection: the engine held
//! here. Serving (routed writes, heads, the rows of a rename through the
//! view) and every background job take its lock for one database step at a
//! time and hold it for nothing else — no disk walk, no hashing, no network,
//! no file moves. Two parts of one daemon that want the database at once
//! queue here instead of inside SQLite, so nothing waits out a busy timeout
//! and no pass fails "busy". Reads never come here: they go to read-only
//! views (the daemon's pool for serving, a view of each job's own).
//!
//! Until D199 every job opened an `Engine` of its own — a second, third,
//! fourth connection in the same process — and folded the log to open it.
//! SQLite takes one writer at a time across connections, so a long write on
//! one (a catalogue install on the NAS) made the others fail after 15 s
//! (D141, D194), and the fold lock turned the daemon's own threads into
//! "another pvfs process folding this forest".

use std::borrow::Cow;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::engine::Engine;
use crate::error::Result;

/// D199 — process-wide counts behind the efficiency figure: how often an
/// engine was opened (each open folds the log), how many read views, and how
/// many folds ran and what they folded. The daemon prints them hourly.
pub struct Counters {
    pub engine_opens: AtomicU64,
    pub read_views: AtomicU64,
    pub folds: AtomicU64,
    pub folded_events: AtomicU64,
}

pub static COUNTERS: Counters = Counters {
    engine_opens: AtomicU64::new(0),
    read_views: AtomicU64::new(0),
    folds: AtomicU64::new(0),
    folded_events: AtomicU64::new(0),
};

impl Counters {
    /// The counts so far, as `(engine opens, read views, folds, events folded)`.
    pub fn read(&self) -> (u64, u64, u64, u64) {
        (
            self.engine_opens.load(Ordering::Relaxed),
            self.read_views.load(Ordering::Relaxed),
            self.folds.load(Ordering::Relaxed),
            self.folded_events.load(Ordering::Relaxed),
        )
    }
}

/// A hold or a wait at least this long is said in the journal (the brief's
/// "any hold of the writer over 1 s is logged with the job and its
/// duration"). `PVFS_WRITER_HOLD_LOG_MS` lowers it for a test.
fn log_threshold() -> Duration {
    static T: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *T.get_or_init(|| {
        std::env::var("PVFS_WRITER_HOLD_LOG_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_secs(1))
    })
}

/// A wait at least this long counts as slow in the hourly figure.
const SLOW_WAIT: Duration = Duration::from_millis(100);

/// The longest a job lets waiting served ops go first before it takes its
/// turn anyway: serving goes first, but a steady stream of it must not stop
/// a job for good.
const GATE_MAX: Duration = Duration::from_secs(2);

/// What the writer did since the figure was last taken.
#[derive(Debug, Clone, Default)]
pub struct WriterStats {
    /// Holds of the lock (steps and served ops).
    pub steps: u64,
    /// Time held, in all.
    pub held: Duration,
    /// The longest hold, and whose.
    pub longest: Duration,
    pub longest_by: String,
    /// Waits of `SLOW_WAIT` or more, the longest, and whose.
    pub slow_waits: u64,
    pub longest_wait: Duration,
    pub longest_wait_by: String,
}

/// D199 §2.8 — how a job thread the daemon lowered below serving (D191) is
/// raised while it holds the writer, and put back after: `raise` runs when a
/// job takes the writer and returns what `restore` needs when the hold ends
/// (`None`: nothing was changed). A served write waiting on a step must not
/// wait on a thread the disk and CPU schedulers are told to starve.
pub type HoldRaise = (fn() -> Option<u64>, fn(u64));

/// The daemon's one writer engine and its lock (D199).
pub struct Writer {
    engine: Mutex<Engine>,
    data_dir: PathBuf,
    /// Served ops waiting for the engine: a job about to take it lets them
    /// go first, so a served write waits for the one step in progress at
    /// most. `std`'s mutex is not fair — a job taking step after step would
    /// otherwise barge ahead of a write that has been waiting.
    serving_waiting: Mutex<usize>,
    serving_done: Condvar,
    /// Who holds the lock now, and who held it last — a slow waiter is told
    /// the holder it waited out.
    holder: Mutex<Option<Cow<'static, str>>>,
    last_holder: Mutex<Option<Cow<'static, str>>>,
    stats: Mutex<WriterStats>,
    poison_said: AtomicBool,
    /// Test seam (`trace_waits`): every acquisition's name and wait, and
    /// every hold's name and length.
    trace: Mutex<Option<Vec<(String, Duration)>>>,
    holds: Mutex<Option<Vec<(String, Duration)>>>,
    hold_raise: Mutex<Option<HoldRaise>>,
}

/// One hold of the writer: the engine, for as long as this lives.
pub struct Held<'a> {
    engine: MutexGuard<'a, Engine>,
    writer: &'a Writer,
    what: Cow<'static, str>,
    since: Instant,
    /// A job thread raised for this hold, and how to put it back.
    raised: Option<(fn(u64), u64)>,
}

impl std::ops::Deref for Held<'_> {
    type Target = Engine;
    fn deref(&self) -> &Engine {
        &self.engine
    }
}

impl std::ops::DerefMut for Held<'_> {
    fn deref_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        // Still held while this runs: the engine's guard drops after it.
        self.writer.released(&self.what, self.since.elapsed());
        if let Some((restore, token)) = self.raised.take() {
            restore(token);
        }
    }
}

impl Writer {
    /// The writer for `engine` — the daemon's, opened (and its log folded)
    /// once, at start.
    pub fn new(engine: Engine) -> Writer {
        let data_dir = engine.data_dir().to_path_buf();
        Writer {
            engine: Mutex::new(engine),
            data_dir,
            serving_waiting: Mutex::new(0),
            serving_done: Condvar::new(),
            holder: Mutex::new(None),
            last_holder: Mutex::new(None),
            stats: Mutex::new(WriterStats::default()),
            poison_said: AtomicBool::new(false),
            trace: Mutex::new(None),
            holds: Mutex::new(None),
            hold_raise: Mutex::new(None),
        }
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// A read-only view of the same forest: what a job reads through, so its
    /// reads never wait on this lock (and never take a slot of the daemon's
    /// serving pool).
    pub fn read_view(&self) -> Result<Engine> {
        Engine::open_read_view(&self.data_dir)
    }

    /// Take the writer for a served op — a request some box or client is
    /// waiting on. Named for the hold-time log (`serve: commit`, …).
    pub fn lock_serving(&self, what: impl Into<Cow<'static, str>>) -> Held<'_> {
        let what = what.into();
        let asked = Instant::now();
        *self.serving_waiting.lock().unwrap_or_else(|p| p.into_inner()) += 1;
        let engine = self.take();
        {
            let mut n = self.serving_waiting.lock().unwrap_or_else(|p| p.into_inner());
            *n -= 1;
            if *n == 0 {
                self.serving_done.notify_all();
            }
        }
        self.acquired(engine, what, asked)
    }

    /// Take the writer for one step of a background job. Served ops waiting
    /// for it go first (up to `GATE_MAX`).
    pub fn lock_job(&self, what: impl Into<Cow<'static, str>>) -> Held<'_> {
        let what = what.into();
        let asked = Instant::now();
        {
            let mut n = self.serving_waiting.lock().unwrap_or_else(|p| p.into_inner());
            while *n > 0 {
                let left = GATE_MAX.saturating_sub(asked.elapsed());
                if left.is_zero() {
                    break;
                }
                n = self
                    .serving_done
                    .wait_timeout(n, left)
                    .map(|(g, _)| g)
                    .unwrap_or_else(|p| p.into_inner().0);
            }
        }
        let engine = self.take();
        let raise = *self.hold_raise.lock().unwrap_or_else(|p| p.into_inner());
        let raised = raise.and_then(|(raise, restore)| raise().map(|token| (restore, token)));
        let mut held = self.acquired(engine, what, asked);
        held.raised = raised;
        held
    }

    /// D199 §2.8 — raise job threads for their holds (`None`: leave them as
    /// they are). pvfsd sets it when its background runs lowered.
    pub fn set_hold_raise(&self, raise: Option<HoldRaise>) {
        *self.hold_raise.lock().unwrap_or_else(|p| p.into_inner()) = raise;
    }

    /// One step of a background job: the writer for as long as `f` runs.
    pub fn step<R>(&self, what: impl Into<Cow<'static, str>>, f: impl FnOnce(&mut Engine) -> R) -> R {
        let mut held = self.lock_job(what);
        f(&mut held)
    }

    /// Test seam: from now on (`on`), record every acquisition's name and
    /// how long it waited, for [`Writer::take_waits`] — how D199's latency
    /// test reads the wait of each served write.
    #[doc(hidden)]
    pub fn trace_waits(&self, on: bool) {
        *self.trace.lock().unwrap_or_else(|p| p.into_inner()) = on.then(Vec::new);
        *self.holds.lock().unwrap_or_else(|p| p.into_inner()) = on.then(Vec::new);
    }

    /// Test seam: the holds recorded since the last call (name, length).
    #[doc(hidden)]
    pub fn take_holds(&self) -> Vec<(String, Duration)> {
        self.holds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// Test seam: the waits recorded since the last call.
    #[doc(hidden)]
    pub fn take_waits(&self) -> Vec<(String, Duration)> {
        self.trace
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// What the writer did since the last call, and a fresh start.
    pub fn take_stats(&self) -> WriterStats {
        std::mem::take(&mut *self.stats.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// The engine itself, when the writer is no longer shared (a runner that
    /// opened its own closes it). `Err` gives the writer back.
    pub fn into_engine(this: Arc<Writer>) -> std::result::Result<Engine, Arc<Writer>> {
        Arc::try_unwrap(this).map(|w| w.engine.into_inner().unwrap_or_else(|p| p.into_inner()))
    }

    /// The lock. A step that panicked while holding it rolled its
    /// transaction back as the panic unwound (a rusqlite transaction rolls
    /// back when dropped), so the engine is taken as it is — once said.
    /// `lock().unwrap()` used to turn one panicking request into a daemon
    /// whose every later write panicked.
    fn take(&self) -> MutexGuard<'_, Engine> {
        match self.engine.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                if !self.poison_said.swap(true, Ordering::SeqCst) {
                    eprintln!(
                        "pvfsd: a step panicked while it held the writer; its transaction was \
                         rolled back and the writer carries on"
                    );
                }
                self.engine.clear_poison();
                poisoned.into_inner()
            }
        }
    }

    fn acquired<'a>(&'a self, engine: MutexGuard<'a, Engine>, what: Cow<'static, str>, asked: Instant) -> Held<'a> {
        let waited = asked.elapsed();
        *self.holder.lock().unwrap_or_else(|p| p.into_inner()) = Some(what.clone());
        if let Some(t) = self.trace.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
            t.push((what.to_string(), waited));
        }
        if waited >= SLOW_WAIT {
            let mut s = self.stats.lock().unwrap_or_else(|p| p.into_inner());
            s.slow_waits += 1;
            if waited > s.longest_wait {
                s.longest_wait = waited;
                s.longest_wait_by = what.to_string();
            }
        }
        if waited >= log_threshold() {
            // The last holder is the one it waited out (the last of several,
            // when several went before it).
            eprintln!(
                "pvfsd: {what} waited {} for the writer (last held by {})",
                secs(waited),
                self.last_holder.lock().unwrap_or_else(|p| p.into_inner()).as_deref().unwrap_or("nobody")
            );
        }
        Held { engine, writer: self, what, since: Instant::now(), raised: None }
    }

    fn released(&self, what: &str, held: Duration) {
        {
            let mut h = self.holder.lock().unwrap_or_else(|p| p.into_inner());
            *self.last_holder.lock().unwrap_or_else(|p| p.into_inner()) = h.take();
        }
        if let Some(t) = self.holds.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
            t.push((what.to_string(), held));
        }
        let mut s = self.stats.lock().unwrap_or_else(|p| p.into_inner());
        s.steps += 1;
        s.held += held;
        if held > s.longest {
            s.longest = held;
            s.longest_by = what.to_string();
        }
        drop(s);
        if held >= log_threshold() {
            eprintln!("pvfsd: the writer was held {} by {what}", secs(held));
        }
    }
}

/// A duration as the journal says it: `2.4 s`, or `180 ms` under a second.
pub fn secs(d: Duration) -> String {
    if d >= Duration::from_secs(1) {
        format!("{:.1} s", d.as_secs_f64())
    } else {
        format!("{} ms", d.as_millis())
    }
}

/// D199 — how a pass reaches the database: reads that never wait on the
/// writer, and write steps that hold it for as long as they run. The same
/// pass code runs on an engine the caller owns (the CLI, tests: `OwnDb`) and
/// in the daemon (`SharedDb`: a read view, and the daemon's writer).
pub trait Db {
    /// A read. `f` sees the forest as committed; in the daemon it runs on a
    /// read-only view, never under the writer.
    fn read<R>(&self, f: impl FnOnce(&Engine) -> Result<R>) -> Result<R>;
    /// One write step, named for the hold-time log: the writer for as long
    /// as `f` runs. Nothing slow belongs in `f`.
    fn write<R>(&self, what: &str, f: impl FnOnce(&mut Engine) -> Result<R>) -> Result<R>;
}

/// An engine the caller owns: reads and writes both run on it, as before
/// D199. Steps are not nested (a `read` inside a `write` would panic).
pub struct OwnDb<'e> {
    engine: RefCell<&'e mut Engine>,
}

impl<'e> OwnDb<'e> {
    pub fn new(engine: &'e mut Engine) -> OwnDb<'e> {
        OwnDb { engine: RefCell::new(engine) }
    }
}

impl Db for OwnDb<'_> {
    fn read<R>(&self, f: impl FnOnce(&Engine) -> Result<R>) -> Result<R> {
        f(&self.engine.borrow())
    }

    fn write<R>(&self, _what: &str, f: impl FnOnce(&mut Engine) -> Result<R>) -> Result<R> {
        f(&mut self.engine.borrow_mut())
    }
}

/// The daemon's writer and a read view of the pass's own (D199): what a
/// job's pass reaches the database through. `job` prefixes every step's name
/// (`watch: rows`, `catalogue: install …`).
pub struct SharedDb {
    writer: Arc<Writer>,
    view: Engine,
    job: &'static str,
}

impl SharedDb {
    /// A pass of `job` on `writer`, with a fresh read view.
    pub fn new(writer: Arc<Writer>, job: &'static str) -> Result<SharedDb> {
        let view = writer.read_view()?;
        Ok(SharedDb { writer, view, job })
    }

    pub fn writer(&self) -> &Arc<Writer> {
        &self.writer
    }

    /// The read view itself, for code that takes an `&Engine` and only reads.
    pub fn view(&self) -> &Engine {
        &self.view
    }

    pub fn job(&self) -> &'static str {
        self.job
    }
}

impl Db for SharedDb {
    fn read<R>(&self, f: impl FnOnce(&Engine) -> Result<R>) -> Result<R> {
        f(&self.view)
    }

    fn write<R>(&self, what: &str, f: impl FnOnce(&mut Engine) -> Result<R>) -> Result<R> {
        let mut held = self.writer.lock_job(format!("{}: {what}", self.job));
        f(&mut held)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer() -> (tempfile::TempDir, Arc<Writer>) {
        let dir = tempfile::tempdir().unwrap();
        let (engine, _) = Engine::init(dir.path()).unwrap();
        (dir, Arc::new(Writer::new(engine)))
    }

    /// D199 — a job taking step after step lets a waiting served op go
    /// first: the op waits for the step in progress, not for the job's
    /// whole run of steps (std's mutex alone lets the job barge ahead).
    #[test]
    fn serving_goes_first() {
        let (_dir, w) = writer();
        let stop = Arc::new(AtomicBool::new(false));
        let job = {
            let (w, stop) = (Arc::clone(&w), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut steps = 0u32;
                while !stop.load(Ordering::SeqCst) && steps < 200 {
                    w.step("job: step", |_| std::thread::sleep(Duration::from_millis(40)));
                    steps += 1;
                }
                steps
            })
        };
        std::thread::sleep(Duration::from_millis(150));
        let mut worst = Duration::ZERO;
        for _ in 0..10 {
            let asked = Instant::now();
            drop(w.lock_serving("serve: probe"));
            worst = worst.max(asked.elapsed());
            std::thread::sleep(Duration::from_millis(15));
        }
        stop.store(true, Ordering::SeqCst);
        assert!(job.join().unwrap() > 3, "the job kept stepping");
        // One 40 ms step in progress at most, with room for a slow box.
        assert!(worst < Duration::from_millis(400), "a served op waited {worst:?} behind a job's steps");
    }

    /// D199 — the figure says who held the writer longest and who waited.
    #[test]
    fn the_figure_names_the_longest_hold_and_the_slow_waits() {
        let (_dir, w) = writer();
        w.trace_waits(true);
        let holder = {
            let w = Arc::clone(&w);
            std::thread::spawn(move || w.step("catalogue: install test", |_| std::thread::sleep(Duration::from_millis(300))))
        };
        std::thread::sleep(Duration::from_millis(50));
        drop(w.lock_serving("serve: commit"));
        holder.join().unwrap();
        let st = w.take_stats();
        assert_eq!(st.steps, 2);
        assert!(st.longest >= Duration::from_millis(300));
        assert_eq!(st.longest_by, "catalogue: install test");
        assert_eq!(st.slow_waits, 1, "{st:?}");
        assert_eq!(st.longest_wait_by, "serve: commit");
        let waits = w.take_waits();
        assert!(waits.iter().any(|(who, d)| who == "serve: commit" && *d >= Duration::from_millis(100)), "{waits:?}");
        assert_eq!(w.take_stats().steps, 0, "taking the figure starts a fresh one");
    }

    /// D199 — a step that panics does not take the daemon's writer with it.
    #[test]
    fn a_step_that_panics_leaves_the_writer_usable() {
        let (_dir, w) = writer();
        let w2 = Arc::clone(&w);
        let r = std::thread::spawn(move || w2.step("job: panics", |_| panic!("a bug in a step"))).join();
        assert!(r.is_err());
        let tip = w.lock_serving("serve: after").log_tip().unwrap();
        assert!(tip > 0);
    }
}
