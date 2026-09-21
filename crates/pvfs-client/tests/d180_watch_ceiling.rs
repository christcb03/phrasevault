//! D180 — a stream of writes under a region root no longer holds the watch off.
//!
//! The watch started a pass only after its debounce of quiet, and every
//! inotify event under the root restarted it — including writes to a `.pvfs-`
//! folder the walk never looks at. On mediabox (D168) rclone copying into
//! `/mnt/local/Media/.pvfs-d168-incoming/` held every pass off for over half
//! an hour; on the NAS, `receive` writes its partials into
//! `<library>/.pvfs-incoming/` for as long as a pull runs. Now what the walk
//! passes over is no change, and changes that never stop start a pass once
//! the first is `ceiling` old.
//!
//! The real `watch::run` on a real catalogue region, with a short debounce and
//! ceiling so the test is quick, and a writer appending a byte every 100 ms.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use pvfs_client::watch::{self, WatchEvent};
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

const DEBOUNCE: Duration = Duration::from_millis(1_000);
const CEILING: Duration = Duration::from_millis(4_000);
/// How late a pass may start and still pass: a loaded CI runner is slow, and
/// what is tested is that the pass comes, not a stopwatch.
const SLACK: Duration = Duration::from_secs(5);
/// The writer's pace: ten times inside the debounce.
const EVERY: Duration = Duration::from_millis(100);

/// A catalogue region bound at `<dir>/lib`, with the folders the writers use
/// made before the watch starts (a folder made after is watched only once
/// notify has seen it made, and a write in between is lost).
fn forest(dir: &Path) -> (PathBuf, PathBuf) {
    let lib = dir.join("lib");
    std::fs::create_dir_all(lib.join("busy")).unwrap();
    std::fs::create_dir_all(lib.join(".pvfs-incoming")).unwrap();
    let data = dir.join("forest");
    let (mut e, _mn) = Engine::init(&data).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Library".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    e.region_mark_as(&region, "catalogue", None).unwrap();
    e.bind_folder(
        &region,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.close().unwrap();
    (data, lib)
}

/// What the test watches for, with when the watch said it.
enum Seen {
    Started(Instant),
    Ended(Instant),
    Watching,
}

struct Watch {
    stop: Arc<AtomicBool>,
    seen: Receiver<Seen>,
    handle: JoinHandle<()>,
}

impl Watch {
    /// `watch::run` on its own thread, returned once its startup pass is over
    /// and every watch is registered.
    fn start(data: PathBuf) -> Watch {
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, seen) = mpsc::channel();
        let flag = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            watch::run(
                &data,
                3600,
                DEBOUNCE.as_millis() as u64,
                CEILING.as_millis() as u64,
                &flag,
                |ev| {
                    let now = Instant::now();
                    let s = match ev {
                        WatchEvent::PassStarted => Seen::Started(now),
                        WatchEvent::Ingested(..)
                        | WatchEvent::Stopped(..)
                        | WatchEvent::Quiet
                        | WatchEvent::ScanError(_) => Seen::Ended(now),
                        WatchEvent::Watching(..) => Seen::Watching,
                        WatchEvent::NeedsAttention(..) => return,
                    };
                    let _ = tx.send(s);
                },
            )
            .unwrap();
        });
        let w = Watch { stop, seen, handle };
        let by = Instant::now() + Duration::from_secs(30);
        loop {
            match w.seen.recv_timeout(by.saturating_duration_since(Instant::now())) {
                Ok(Seen::Watching) => return w,
                Ok(_) => {}
                Err(e) => panic!("the watch never started watching: {e}"),
            }
        }
    }

    /// When the next pass started, if one did by `by`.
    fn next_start(&self, by: Instant) -> Option<Instant> {
        self.next(by, |s| match s {
            Seen::Started(t) => Some(*t),
            _ => None,
        })
    }

    /// When the next pass ended, if one did by `by`.
    fn next_end(&self, by: Instant) -> Option<Instant> {
        self.next(by, |s| match s {
            Seen::Ended(t) => Some(*t),
            _ => None,
        })
    }

    fn next(&self, by: Instant, want: impl Fn(&Seen) -> Option<Instant>) -> Option<Instant> {
        loop {
            let s = self.seen.recv_timeout(by.checked_duration_since(Instant::now())?).ok()?;
            if let Some(t) = want(&s) {
                return Some(t);
            }
        }
    }

    fn end(self) {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.join().unwrap();
    }
}

/// A byte appended to `path` every `EVERY` until dropped. `first` is when the
/// first was written; `max_gap_ms` the longest the writer has gone without,
/// which says whether the stream really was continuous on a busy runner.
struct Writer {
    first: Instant,
    max_gap_ms: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Writer {
    fn start(path: &Path) -> Writer {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
        f.write_all(b"x").unwrap();
        let first = Instant::now();
        let max_gap_ms = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (gap, flag) = (Arc::clone(&max_gap_ms), Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            let mut last = first;
            while !flag.load(Ordering::SeqCst) {
                std::thread::sleep(EVERY);
                f.write_all(b"x").unwrap();
                let now = Instant::now();
                gap.fetch_max(now.duration_since(last).as_millis() as u64, Ordering::SeqCst);
                last = now;
            }
        });
        Writer { first, max_gap_ms, stop, handle: Some(handle) }
    }

    /// Whether every gap so far was well inside the debounce.
    fn continuous(&self) -> bool {
        self.max_gap_ms.load(Ordering::SeqCst) < (DEBOUNCE.as_millis() as u64) * 8 / 10
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Changes to content that never stop for the debounce start a pass at the
/// ceiling — not before (the debounce never runs out), and not an hour later
/// (the old loop). And again, a ceiling after that pass ends, while the writes
/// go on.
#[test]
fn a_stream_of_content_writes_starts_a_pass_at_the_ceiling() {
    let dir = tempfile::tempdir().unwrap();
    let (data, lib) = forest(dir.path());
    let w = Watch::start(data);

    let writer = Writer::start(&lib.join("busy/stream.bin"));
    let s1 = w
        .next_start(writer.first + CEILING + SLACK)
        .expect("no pass started while the writes went on (the debounce never ran out)");
    let waited = s1.saturating_duration_since(writer.first);
    if writer.continuous() {
        assert!(
            waited + Duration::from_millis(100) >= CEILING,
            "the pass started after {waited:?}: before the ceiling, so not because of it"
        );
    }

    let e1 = w.next_end(s1 + SLACK + SLACK).expect("the pass never ended");
    let s2 = w
        .next_start(e1 + CEILING + SLACK)
        .expect("no second pass while the writes still went on");
    let between = s2.saturating_duration_since(e1);
    if writer.continuous() {
        assert!(between >= CEILING, "the next pass came {between:?} after the last one ended");
    }

    drop(writer);
    w.end();
}

/// Writes under `.pvfs-incoming` — receive's partials — are no change at all:
/// no pass for longer than the ceiling while they go on. A file placed in the
/// library then starts one once the debounce runs out, with the writes still
/// going.
#[test]
fn writes_under_a_pvfs_folder_start_no_pass_and_hold_none_off() {
    let dir = tempfile::tempdir().unwrap();
    let (data, lib) = forest(dir.path());
    let w = Watch::start(data);

    let writer = Writer::start(&lib.join(".pvfs-incoming/ab12.partial"));
    let quiet_until = writer.first + CEILING + Duration::from_secs(2);
    if let Some(t) = w.next_start(quiet_until) {
        panic!(
            "a pass started {:?} into writes the walk never looks at",
            t.saturating_duration_since(writer.first)
        );
    }

    std::fs::write(lib.join("a.mkv"), b"a new episode").unwrap();
    let placed = Instant::now();
    let s = w
        .next_start(placed + DEBOUNCE + SLACK)
        .expect("a file placed in the library started no pass while the partial was written");
    assert!(
        s.saturating_duration_since(placed) + Duration::from_millis(100) >= DEBOUNCE,
        "the pass did not wait for the debounce"
    );

    drop(writer);
    w.end();
}
