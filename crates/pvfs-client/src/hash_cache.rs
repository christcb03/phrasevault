//! D165 — the view mount's read-through cache (doc 26 phase 6; PVOS D164 §3).
//!
//! A file the mount does not hold is fetched **by the read that asked**: the
//! file is a map of pieces over a sparse `<hash>.partial` in the hash store,
//! a read registers the pieces it covers as demand, and the fetch's worker
//! asks a holder for exactly the missing run (`CatHash` is ranged). A media
//! scan reads the first few dozen KB and the last KB of every file (Sonarr's
//! ffprobe, traced — PVOS D164 §1c); before D165 each such read pulled the
//! whole file from byte 0 and the tail read waited on all of it.
//!
//! * **Readahead** only once a reader is sequential, doubling to a ceiling.
//! * **Complete on consumption**: a reader that has consumed
//!   `complete_after` bytes in a row is a consumer, not a probe, and the
//!   worker completes the file in the background. All pieces present → the
//!   partial is hashed and only a match is renamed into the store; a
//!   mismatch is refused, the box NAMED and skipped, the next one asked.
//! * **Stop when the application is done**: the last handle closing ends a
//!   probe's fetch at once; a completing fetch runs on for a grace, then
//!   stops unless it is nearly through.
//! * **At most `streams` requests on the network**, demand before
//!   background; connections pooled per holder.
//! * **Bounded**: `max_bytes` of allocated blocks and `max_age` unread,
//!   least recently read first (an entry's mtime is its last open), never
//!   an entry with an open handle or a live fetch.
//!
//! Piece maps live in memory: a restart forgets probes (every leftover
//! `.partial` is swept when the cache is made) and keeps complete files.
//!
//! **Stream mode** (PVOS D181 — Plex on the LAN, Chris: no cache) keeps
//! nothing: no background completion; readahead stays ahead of each
//! sequential reader instead of waiting for it to run out; pieces more than
//! `behind` bytes behind every reader are punched out of the partial; and
//! the partial is deleted when the file's last handle closes. A file's disk
//! use is its readers' windows, not what they have read.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use pvfs_core::{Engine, ReplicaSource};

use crate::ClientError;

/// What the cache keeps (PVOS D181).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheMode {
    /// D165: a consumer's file is completed, verified and kept under the bound.
    #[default]
    Keep,
    /// D181: only what readers are reading, dropped behind them and at close.
    Stream,
}

impl std::str::FromStr for CacheMode {
    type Err = String;
    fn from_str(s: &str) -> Result<CacheMode, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "keep" => Ok(CacheMode::Keep),
            "stream" => Ok(CacheMode::Stream),
            other => Err(format!("{other:?}: the cache mode is `keep` or `stream`")),
        }
    }
}

impl std::fmt::Display for CacheMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CacheMode::Keep => "keep",
            CacheMode::Stream => "stream",
        })
    }
}

/// A stream-mode reader not heard from in this long no longer holds pieces
/// behind it. Above the mount's longest wait for a read (120 s), so a read
/// that waited is never punched between being told "here" and reading.
const CURSOR_IDLE: Duration = Duration::from_secs(300);
/// Sequential readers tracked per file (Plex's player, its analysers).
const MAX_CURSORS: usize = 16;

/// The cache's knobs. `Default` is production (PVOS D164 §3, Chris's numbers
/// for the bound: 500 GB, one day); tests shrink them.
#[derive(Debug, Clone)]
pub struct CacheOpts {
    /// D181: keep what was read (D165), or stream it through.
    pub mode: CacheMode,
    /// Stream mode: pieces this far behind every reader are dropped.
    pub behind: u64,
    /// The unit a file is fetched and mapped in.
    pub piece: u64,
    /// The most a sequential reader is read ahead of.
    pub max_readahead: u64,
    /// Bytes consumed in a row that make a reader a consumer: the file is
    /// then completed in the background. Files no larger than this are also
    /// verified whole BEFORE their last piece is served.
    pub complete_after: u64,
    /// The size of one background request (a waiting read gets the network
    /// between bursts).
    pub burst: u64,
    /// How long a completing fetch runs on after its last handle closes.
    pub grace: Duration,
    /// …unless it already has this share of the file, when it finishes.
    pub finish_percent: u64,
    /// Requests on the network at once.
    pub streams: usize,
    /// The bound: allocated bytes under `by-hash/`, partials included.
    pub max_bytes: u64,
    /// The bound: an entry unread this long goes.
    pub max_age: Duration,
    /// How often the janitor applies the bound.
    pub janitor_every: Duration,
    /// A pause between background bursts. Zero in production; a test's way
    /// to watch a fetch that a local socket would finish in milliseconds.
    pub background_pause: Duration,
}

impl Default for CacheOpts {
    fn default() -> CacheOpts {
        CacheOpts {
            mode: CacheMode::Keep,
            behind: 64 << 20,
            piece: 1 << 20,
            max_readahead: 8 << 20,
            complete_after: 64 << 20,
            burst: 32 << 20,
            grace: Duration::from_secs(60),
            finish_percent: 75,
            streams: 4,
            max_bytes: 500_000_000_000,
            max_age: Duration::from_secs(24 * 60 * 60),
            janitor_every: Duration::from_secs(300),
            background_pause: Duration::ZERO,
        }
    }
}

/// Which pieces of a file are on disk.
struct Pieces {
    bits: Vec<u64>,
    n: usize,
    have: usize,
}

impl Pieces {
    fn new(n: usize) -> Pieces {
        Pieces {
            bits: vec![0; n.div_ceil(64)],
            n,
            have: 0,
        }
    }

    fn get(&self, i: usize) -> bool {
        i < self.n && ((self.bits[i / 64] >> (i % 64)) & 1) == 1
    }

    fn set(&mut self, i: usize) {
        if i < self.n && !self.get(i) {
            self.bits[i / 64] |= 1 << (i % 64);
            self.have += 1;
        }
    }

    fn all(&self) -> bool {
        self.have == self.n
    }

    fn unset(&mut self, i: usize) {
        if self.get(i) {
            self.bits[i / 64] &= !(1 << (i % 64));
            self.have -= 1;
        }
    }

    fn clear(&mut self) {
        self.bits.iter_mut().for_each(|w| *w = 0);
        self.have = 0;
    }

    /// The first missing piece in `[from, to]`.
    fn first_missing(&self, from: usize, to: usize) -> Option<usize> {
        (from..=to.min(self.n.saturating_sub(1))).find(|&i| !self.get(i))
    }
}

/// `streams` permits, demand before background: a background burst waits
/// while any read is waiting for a permit.
struct Gate {
    st: Mutex<GateSt>,
    cv: Condvar,
}

struct GateSt {
    free: usize,
    demand_waiting: usize,
}

struct Permit<'a>(&'a Gate);

impl Gate {
    fn new(streams: usize) -> Gate {
        Gate {
            st: Mutex::new(GateSt {
                free: streams.max(1),
                demand_waiting: 0,
            }),
            cv: Condvar::new(),
        }
    }

    fn acquire(&self, demand: bool) -> Permit<'_> {
        let mut st = self.st.lock().unwrap();
        if demand {
            st.demand_waiting += 1;
            while st.free == 0 {
                st = self.cv.wait(st).unwrap();
            }
            st.demand_waiting -= 1;
        } else {
            while st.free == 0 || st.demand_waiting > 0 {
                st = self.cv.wait(st).unwrap();
            }
        }
        st.free -= 1;
        Permit(self)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.0.st.lock().unwrap().free += 1;
        self.0.cv.notify_all();
    }
}

/// D181 — one sequential reader of a stream-mode file: where its last read
/// started and ended, the bytes it has read in a row, and when.
struct Cursor {
    off: u64,
    end: u64,
    run: u64,
    at: Instant,
}

/// One waiting read: the pieces it covers and how far past them to fetch.
struct Demand {
    id: u64,
    first: usize,
    last: usize,
    ahead: usize,
}

struct FetchSt {
    pieces: Pieces,
    demands: Vec<Demand>,
    next_demand: u64,
    handles: usize,
    last_close: Option<Instant>,
    completing: bool,
    /// Where the last read ended, and how many bytes have been read in a row.
    seq_end: u64,
    seq_bytes: u64,
    worker: bool,
    finished: Option<Result<PathBuf, String>>,
    fetched: u64,
    /// A request no box would serve fails the reads that were waiting and
    /// ends the worker — but keeps the pieces: the next read tries again.
    /// `finished` is for the verdict on the whole file.
    fail_gen: u64,
    last_err: String,
    last_fail: Option<Instant>,
    /// Stream mode: the readers, the window kept ahead of them, and the
    /// piece below which the last sweep dropped everything.
    cursors: Vec<Cursor>,
    prefetch: Option<(usize, usize)>,
    swept: usize,
}

/// One file being read through: its piece map, its waiting reads, its worker.
pub struct HashFetch {
    hash: String,
    size: u64,
    part: PathBuf,
    final_path: PathBuf,
    cache: Weak<CacheInner>,
    opts: CacheOpts,
    st: Mutex<FetchSt>,
    cv: Condvar,
}

impl HashFetch {
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Pieces on disk (tests, and the mount's log).
    pub fn pieces_have(&self) -> usize {
        self.st.lock().unwrap().pieces.have
    }

    pub fn pieces_total(&self) -> usize {
        self.st.lock().unwrap().pieces.n
    }

    /// Bytes this fetch has taken off the network.
    pub fn fetched_bytes(&self) -> u64 {
        self.st.lock().unwrap().fetched
    }

    pub fn worker_running(&self) -> bool {
        self.st.lock().unwrap().worker
    }

    /// Whether the fetch ended in failure (the cache retries it at the next
    /// open rather than serving its error until remount).
    pub fn failed(&self) -> bool {
        self.st.lock().unwrap().finished.as_ref().is_some_and(|r| r.is_err())
    }

    /// Why the fetch failed for good, else why its last request did.
    pub fn error(&self) -> Option<String> {
        let st = self.st.lock().unwrap();
        match &st.finished {
            Some(Err(e)) => Some(e.clone()),
            _ => (!st.last_err.is_empty()).then(|| st.last_err.clone()),
        }
    }

    fn handle_opened(&self) {
        let mut st = self.st.lock().unwrap();
        st.handles += 1;
        st.last_close = None;
    }

    /// "The application says it is done": the last close ends a probe's
    /// fetch and starts a completing fetch's grace — in stream mode, it
    /// deletes the partial (now, or when the worker has stopped).
    pub fn handle_closed(self: &Arc<Self>) {
        let last = {
            let mut st = self.st.lock().unwrap();
            st.handles = st.handles.saturating_sub(1);
            if st.handles == 0 {
                st.last_close = Some(Instant::now());
            }
            self.cv.notify_all();
            st.handles == 0
        };
        if last && self.opts.mode == CacheMode::Stream {
            if let Some(cache) = self.cache.upgrade() {
                cache.drop_idle_stream(self);
            }
        }
    }

    /// Stream mode: the partial's allocated bytes (tests, the lab).
    pub fn allocated_bytes(&self) -> u64 {
        std::fs::metadata(&self.part).map(|m| std::os::unix::fs::MetadataExt::blocks(&m) * 512).unwrap_or(0)
    }

    fn span(&self, off: u64, len: u64) -> (usize, usize) {
        let piece = self.opts.piece;
        let end = off.saturating_add(len).min(self.size);
        ((off / piece) as usize, (end.saturating_sub(1) / piece) as usize)
    }

    /// Small files are verified whole before their last piece is served;
    /// above `complete_after` a read is served as its pieces land (hashing
    /// 50 GB would outlast the read's deadline) and the verdict follows.
    fn covered(&self, st: &FetchSt, first: usize, last: usize) -> bool {
        if st.pieces.first_missing(first, last).is_some() {
            return false;
        }
        !(st.pieces.all() && self.size <= self.opts.complete_after)
    }

    fn note_read(&self, st: &mut FetchSt, off: u64, len: u64) -> bool {
        if self.opts.mode == CacheMode::Stream {
            self.note_cursor(st, off, len);
            return false;
        }
        let piece = self.opts.piece;
        let near = off <= st.seq_end.saturating_add(piece) && off.saturating_add(piece) >= st.seq_end;
        if near && st.seq_bytes > 0 {
            st.seq_bytes += len;
        } else {
            st.seq_bytes = len;
        }
        st.seq_end = off.saturating_add(len);
        if st.seq_bytes >= self.opts.complete_after && !st.completing {
            st.completing = true;
            return true;
        }
        false
    }

    /// Stream mode: the read joins the reader it continues (or is a new
    /// one); `seq_bytes` is then THAT reader's run, so two readers of one
    /// file each get their readahead. Then drop what is behind them all.
    fn note_cursor(&self, st: &mut FetchSt, off: u64, len: u64) {
        let piece = self.opts.piece;
        let now = Instant::now();
        st.cursors.retain(|c| now.duration_since(c.at) < CURSOR_IDLE);
        let near = |c: &Cursor| off <= c.end.saturating_add(piece) && off.saturating_add(piece) >= c.end;
        let run = match st.cursors.iter_mut().find(|c| near(c)) {
            Some(c) => {
                c.run = c.run.saturating_add(len);
                (c.off, c.end, c.at) = (off, off.saturating_add(len), now);
                c.run
            }
            None => {
                if st.cursors.len() >= MAX_CURSORS {
                    // the least recently heard from — never the read in hand
                    if let Some(i) = (0..st.cursors.len()).min_by_key(|&i| st.cursors[i].at) {
                        st.cursors.swap_remove(i);
                    }
                }
                st.cursors.push(Cursor {
                    off,
                    end: off.saturating_add(len),
                    run: len,
                    at: now,
                });
                len
            }
        };
        st.seq_bytes = run;
        st.seq_end = off.saturating_add(len);
        self.drop_behind(st);
    }

    /// The pieces a sequential reader is read ahead by (0 for a probe).
    fn ahead(&self, st: &FetchSt) -> usize {
        if st.seq_bytes >= self.opts.piece {
            let pow2 = 1u64 << (63 - st.seq_bytes.leading_zeros());
            (pow2.min(self.opts.max_readahead) / self.opts.piece) as usize
        } else {
            0
        }
    }

    /// Stream mode: punch out every piece more than `behind` bytes behind
    /// the rearmost reader. Under the file's lock, so a piece is never
    /// dropped between a read being told it is here and the read — the
    /// reader's own cursor is at or below what it reads, and the floor is
    /// `behind` below every cursor. Swept each time the floor passes 1/4 of
    /// `behind` more (a backward seek resets it).
    fn drop_behind(&self, st: &mut FetchSt) {
        let piece = self.opts.piece;
        let Some(rear) = st.cursors.iter().map(|c| c.off).min() else { return };
        let below = (rear.saturating_sub(self.opts.behind) / piece) as usize;
        let step = ((self.opts.behind / piece) as usize / 4).max(1);
        if below < st.swept {
            st.swept = below;
        }
        if below < st.swept + step {
            return;
        }
        st.swept = below;
        let mut i = 0;
        while i < below.min(st.pieces.n) {
            if !st.pieces.get(i) {
                i += 1;
                continue;
            }
            let from = i;
            while i < below.min(st.pieces.n) && st.pieces.get(i) {
                i += 1;
            }
            let off = from as u64 * piece;
            let len = (i as u64 * piece).min(self.size) - off;
            if punch(&self.part, off, len) {
                (from..i).for_each(|p| st.pieces.unset(p));
            }
        }
    }

    /// The bytes of `[off, off+len)` if they can be served now — and the
    /// read is counted, which is how a consumer is told from a probe. `None`
    /// means wait ([`HashFetch::wait_range`], off the mount's session thread).
    pub fn poll_range(self: &Arc<Self>, off: u64, len: u64) -> Option<Result<PathBuf, String>> {
        let mut st = self.st.lock().unwrap();
        if let Some(fin) = &st.finished {
            return Some(fin.clone());
        }
        let became_consumer = self.note_read(&mut st, off, len);
        // A completing fetch whose worker ended on a failed request picks
        // up again with the reads — not at the rate of them.
        let rested = st.last_fail.is_none_or(|t| t.elapsed() > Duration::from_secs(5));
        if became_consumer || (st.completing && !st.worker && rested) {
            self.ensure_worker(&mut st);
            self.cv.notify_all();
        }
        if len == 0 || off >= self.size {
            return Some(Ok(self.part.clone()));
        }
        let (first, last) = self.span(off, len);
        let covered = self.covered(&st, first, last);
        if covered && self.opts.mode == CacheMode::Stream {
            // Keep the window ahead of a sequential reader filled, so it
            // never waits at the edge of what was read ahead (D165 waits:
            // it completes the file instead).
            let to = (last + self.ahead(&st)).min(st.pieces.n.saturating_sub(1));
            if to > last && st.pieces.first_missing(last + 1, to).is_some() {
                st.prefetch = Some((last + 1, to));
                self.ensure_worker(&mut st);
                self.cv.notify_all();
            }
        }
        covered.then(|| Ok(self.part.clone()))
    }

    /// Register `[off, off+len)` as demand and wait for it. `Ok(path)` names
    /// where to read: the kept file once finished, else the partial.
    pub fn wait_range(self: &Arc<Self>, off: u64, len: u64, timeout: Duration) -> Result<PathBuf, String> {
        let deadline = Instant::now() + timeout;
        let (first, last) = self.span(off, len);
        let mut st = self.st.lock().unwrap();
        let id = st.next_demand;
        st.next_demand += 1;
        let ahead = self.ahead(&st);
        st.demands.push(Demand { id, first, last, ahead });
        let failures = st.fail_gen;
        self.ensure_worker(&mut st);
        self.cv.notify_all();
        let out = loop {
            if let Some(fin) = &st.finished {
                break fin.clone();
            }
            if st.fail_gen != failures {
                break Err(st.last_err.clone());
            }
            if self.covered(&st, first, last) {
                // (stream mode) heard from now, not when it began waiting
                let now = Instant::now();
                st.cursors.iter_mut().filter(|c| c.off == off).for_each(|c| c.at = now);
                break Ok(self.part.clone());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break Err("timed out waiting for pieces".into());
            }
            let (g, _) = self.cv.wait_timeout(st, left).unwrap();
            st = g;
        };
        st.demands.retain(|d| d.id != id);
        out
    }

    /// [`HashFetch::poll_range`], then [`HashFetch::wait_range`] if it must.
    pub fn read_range(self: &Arc<Self>, off: u64, len: u64, timeout: Duration) -> Result<PathBuf, String> {
        match self.poll_range(off, len) {
            Some(r) => r,
            None => self.wait_range(off, len, timeout),
        }
    }

    fn ensure_worker(self: &Arc<Self>, st: &mut FetchSt) {
        if st.worker || st.finished.is_some() {
            return;
        }
        let Some(cache) = self.cache.upgrade() else {
            st.finished = Some(Err("the read-through cache is gone".into()));
            return;
        };
        st.worker = true;
        let fetch = Arc::clone(self);
        std::thread::spawn(move || worker(cache, fetch));
    }

    fn mark(&self, idx: usize, bytes: u64) {
        let mut st = self.st.lock().unwrap();
        st.pieces.set(idx);
        st.fetched += bytes;
        self.cv.notify_all();
    }

    fn finish(&self, r: Result<PathBuf, String>) {
        let mut st = self.st.lock().unwrap();
        st.finished = Some(r);
        self.cv.notify_all();
    }

    fn open_part(&self) -> Result<std::fs::File, String> {
        if let Some(parent) = self.part.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("hash store: {e}"))?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.part)
            .map_err(|e| format!("hash store: {e}"))?;
        if f.metadata().map(|m| m.len()).unwrap_or(0) != self.size {
            // sparse: only the pieces that land take disk
            f.set_len(self.size).map_err(|e| format!("hash store: {e}"))?;
        }
        Ok(f)
    }
}

enum Job {
    Fetch { first: usize, end: usize, demand: bool },
    Verify,
    Exit,
}

fn next_job(st: &FetchSt, o: &CacheOpts) -> Option<Job> {
    if st.pieces.all() {
        return Some(Job::Verify);
    }
    let n = st.pieces.n;
    for d in &st.demands {
        if let Some(p) = st.pieces.first_missing(d.first, d.last) {
            let limit = (d.last + d.ahead).min(n - 1);
            let mut end = p + 1;
            while end <= limit && !st.pieces.get(end) {
                end += 1;
            }
            return Some(Job::Fetch { first: p, end, demand: true });
        }
    }
    if let (Some((from, to)), true) = (st.prefetch, st.handles > 0) {
        if let Some(p) = st.pieces.first_missing(from, to) {
            let mut end = p + 1;
            while end <= to && !st.pieces.get(end) {
                end += 1;
            }
            return Some(Job::Fetch { first: p, end, demand: false });
        }
    }
    let keep_going = st.handles > 0
        || st.last_close.is_some_and(|t| t.elapsed() < o.grace)
        || st.pieces.have as u64 * 100 >= o.finish_percent * n as u64;
    if st.completing && keep_going {
        let p = st.pieces.first_missing(0, n - 1)?;
        let most = (o.burst / o.piece).max(1) as usize;
        let mut end = p + 1;
        while end < n && end - p < most && !st.pieces.get(end) {
            end += 1;
        }
        return Some(Job::Fetch { first: p, end, demand: false });
    }
    if st.handles == 0 {
        return Some(Job::Exit);
    }
    None
}

/// What one worker remembers between requests.
struct Run {
    cur: usize,
    bad: HashSet<usize>,
    served: HashSet<String>,
    file: Option<std::fs::File>,
    last: String,
}

/// Writes a ranged stream at its offset and marks each piece as it is whole.
struct PieceSink<'a> {
    file: &'a std::fs::File,
    fetch: &'a HashFetch,
    base: u64,
    written: u64,
    next: usize,
}

impl std::io::Write for PieceSink<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use std::os::unix::fs::FileExt;
        self.file.write_all_at(buf, self.base + self.written)?;
        self.written += buf.len() as u64;
        let piece = self.fetch.opts.piece;
        loop {
            let start = self.next as u64 * piece;
            let end = (start + piece).min(self.fetch.size);
            if start >= self.fetch.size || end > self.base + self.written {
                break;
            }
            self.fetch.mark(self.next, end - start);
            self.next += 1;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn worker(cache: Arc<CacheInner>, fetch: Arc<HashFetch>) {
    work(&cache, &fetch);
    if cache.opts.mode == CacheMode::Stream {
        cache.drop_idle_stream(&fetch);
    }
}

fn work(cache: &Arc<CacheInner>, fetch: &Arc<HashFetch>) {
    let sources = cache.sources();
    let mut run = Run {
        cur: cache.hint.load(Ordering::Relaxed),
        bad: HashSet::new(),
        served: HashSet::new(),
        file: None,
        last: "no announced endpoint holds these bytes".into(),
    };
    loop {
        let job = {
            let mut st = fetch.st.lock().unwrap();
            loop {
                if st.finished.is_some() {
                    st.worker = false;
                    return;
                }
                match next_job(&st, &cache.opts) {
                    Some(Job::Exit) => {
                        st.worker = false;
                        fetch.cv.notify_all();
                        return;
                    }
                    Some(job) => break job,
                    None => {
                        let (g, _) = fetch.cv.wait_timeout(st, Duration::from_millis(250)).unwrap();
                        st = g;
                    }
                }
            }
        };
        match job {
            Job::Fetch { first, end, demand } => {
                if let Err(e) = fetch_run(cache, fetch, &sources, &mut run, first, end, demand) {
                    eprintln!("mount: read-through of {} failed: {e}", &fetch.hash[..8]);
                    let mut st = fetch.st.lock().unwrap();
                    st.fail_gen += 1;
                    st.last_err = e;
                    st.last_fail = Some(Instant::now());
                    st.worker = false;
                    fetch.cv.notify_all();
                    return;
                } else if !demand && !cache.opts.background_pause.is_zero() {
                    std::thread::sleep(cache.opts.background_pause);
                }
            }
            Job::Verify => verify(cache, fetch, &sources, &mut run),
            Job::Exit => unreachable!("handled under the lock"),
        }
    }
}

fn fetch_run(
    cache: &CacheInner,
    fetch: &HashFetch,
    sources: &[ReplicaSource],
    run: &mut Run,
    first: usize,
    end: usize,
    demand: bool,
) -> Result<(), String> {
    let piece = cache.opts.piece;
    let off = first as u64 * piece;
    let len = (end as u64 * piece).min(fetch.size) - off;
    let _permit = cache.gate.acquire(demand);
    if run.file.is_none() {
        run.file = Some(fetch.open_part()?);
    }
    let file = run.file.as_ref().expect("opened above");
    for _ in 0..sources.len() {
        let idx = run.cur % sources.len();
        let src = &sources[idx];
        if run.bad.contains(&idx) {
            run.cur += 1;
            continue;
        }
        // A pooled connection may have idled out: one fresh dial before the
        // box is given up on.
        for attempt in 0..2 {
            let pooled = if attempt == 0 { cache.checkout(&src.target) } else { None };
            let from_pool = pooled.is_some();
            let mut client = match pooled {
                Some(c) => c,
                None => match crate::follow::dial_source(src) {
                    Ok(c) => c,
                    Err(e) => {
                        run.last = format!("{}: {e}", src.target);
                        break;
                    }
                },
            };
            let mut sink = PieceSink {
                file,
                fetch,
                base: off,
                written: 0,
                next: first,
            };
            let streamed = client.cat_hash_range(&fetch.hash, off, len, &mut sink);
            let written = sink.written;
            match streamed {
                Ok(_) if written == len => {
                    cache.checkin(&src.target, client);
                    run.served.insert(src.target.clone());
                    cache.fetched.fetch_add(len, Ordering::Relaxed);
                    cache.hint.store(idx, Ordering::Relaxed);
                    return Ok(());
                }
                Ok(_) => {
                    run.last = format!("{}: short stream, {written} of {len} bytes", src.target);
                    break;
                }
                Err(ClientError::Server { code, message }) => {
                    // An error REPLY leaves the connection in control state.
                    cache.checkin(&src.target, client);
                    if code != "not_found" {
                        run.last = format!("{}: {code}: {message}", src.target);
                    }
                    break;
                }
                Err(e) => {
                    run.last = format!("{}: {e}", src.target);
                    if !from_pool {
                        break;
                    }
                }
            }
        }
        run.cur += 1;
    }
    Err(run.last.clone())
}

fn hash_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Every piece is on disk: hash the partial, and only a match is kept. A
/// mismatch is evidence (doc 22 §7) — the boxes that served are named and
/// skipped, and the next one is asked from the start.
fn verify(cache: &CacheInner, fetch: &Arc<HashFetch>, sources: &[ReplicaSource], run: &mut Run) {
    let got = match hash_file(&fetch.part) {
        Ok(h) => h,
        Err(e) => {
            fetch.finish(Err(format!("hash store: {e}")));
            return;
        }
    };
    if got == fetch.hash && cache.opts.mode == CacheMode::Stream {
        // Nothing is kept: the verified partial serves until the last close.
        eprintln!("mount: {} is whole and verified ({} bytes; stream mode keeps nothing)", &fetch.hash[..8], fetch.size);
        fetch.finish(Ok(fetch.part.clone()));
        return;
    }
    if got == fetch.hash {
        drop(run.file.take());
        match std::fs::rename(&fetch.part, &fetch.final_path) {
            Ok(()) => {
                touch(&fetch.final_path);
                cache.completed.fetch_add(1, Ordering::Relaxed);
                eprintln!("mount: {} is whole, verified and kept ({} bytes)", &fetch.hash[..8], fetch.size);
                fetch.finish(Ok(fetch.final_path.clone()));
            }
            Err(e) => fetch.finish(Err(format!("hash store: {e}"))),
        }
        cache.forget(fetch);
        return;
    }
    let mut names: Vec<&str> = run.served.iter().map(String::as_str).collect();
    names.sort_unstable();
    run.last = format!(
        "{} served bytes whose hash is {}, not {} — refused",
        names.join(" and "),
        &got[..got.len().min(16)],
        fetch.hash
    );
    eprintln!("mount: {}", run.last);
    for (i, s) in sources.iter().enumerate() {
        if run.served.contains(&s.target) {
            run.bad.insert(i);
        }
    }
    run.served.clear();
    if run.bad.len() >= sources.len() {
        drop(run.file.take());
        let _ = std::fs::remove_file(&fetch.part);
        fetch.finish(Err(run.last.clone()));
        cache.forget(fetch);
        return;
    }
    // Start again from the next box: nothing a refused box sent is kept.
    if let Some(f) = run.file.as_ref() {
        let _ = f.set_len(0);
        let _ = f.set_len(fetch.size);
    }
    let mut st = fetch.st.lock().unwrap();
    st.pieces.clear();
    st.completing = true;
}

fn touch(path: &Path) {
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.set_modified(SystemTime::now());
    }
}

/// D181 — give `[off, off+len)` of a sparse partial back to the disk. False
/// (the piece stays marked, its bytes intact) where holes cannot be punched.
#[cfg(target_os = "linux")]
fn punch(path: &Path, off: u64, len: u64) -> bool {
    use nix::fcntl::{fallocate, FallocateFlags};
    use std::os::fd::AsRawFd;
    let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) else { return false };
    let flags = FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE;
    match fallocate(f.as_raw_fd(), flags, off as i64, len as i64) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("mount: cannot drop read pieces of {}: {e}", path.display());
            false
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn punch(_path: &Path, _off: u64, _len: u64) -> bool {
    false
}

/// The fleet's other boxes, as the forest at `data_dir` knows them: every
/// announced endpoint minus this box, in pin order (D130's rule).
pub fn announced_sources(data_dir: &Path) -> Vec<ReplicaSource> {
    let Ok(engine) = Engine::open(data_dir) else {
        return Vec::new();
    };
    let own = pvfs_core::storage::host_pin(data_dir);
    let mut eps: Vec<(String, String)> = crate::fetch::catalog_endpoints(&engine)
        .into_iter()
        .filter(|(pin, _)| own.as_deref() != Some(pin.as_str()))
        .collect();
    let _ = engine.close();
    eps.sort();
    eps.into_iter()
        .map(|(pin, addr)| ReplicaSource {
            transport: "tcp".into(),
            target: addr,
            pin,
            region: String::new(),
        })
        .collect()
}

/// Which announced box last answered for a region (other than "not mine").
static HOLDER_HINT: std::sync::Mutex<std::collections::BTreeMap<String, String>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Ask the fleet, box by box, to do `ask` on the box that holds region `r`,
/// over the connections in `open` (dialed as needed, kept for the next
/// item): `not_found` = "not mine", try the next; any other refusal is the
/// answer. `Err` carries why.
fn ask_holder<T>(
    open: &mut HashMap<String, crate::Client>,
    sources: &[ReplicaSource],
    r: &str,
    mut ask: impl FnMut(&mut crate::Client) -> std::result::Result<T, ClientError>,
) -> Result<T, String> {
    let mut why = format!("no box that holds region {} answered", &r[..r.len().min(8)]);
    // The box that answered for this region last time is asked first: an
    // arr renaming a season is a hundred requests for one region, and
    // every box asked in vain is a dial — a second, from feederbox.
    let hinted = HOLDER_HINT.lock().unwrap().get(r).cloned();
    let mut order: Vec<&ReplicaSource> = sources.iter().collect();
    if let Some(h) = &hinted {
        order.sort_by_key(|s| &s.target != h);
    }
    for src in order {
        if !open.contains_key(&src.target) {
            match crate::follow::dial_source(src) {
                Ok(c) => {
                    open.insert(src.target.clone(), c);
                }
                Err(e) => {
                    why = format!("{}: {e}", src.target);
                    continue;
                }
            }
        }
        let client = open.get_mut(&src.target).expect("dialed above");
        match ask(client) {
            Ok(v) => {
                HOLDER_HINT.lock().unwrap().insert(r.to_string(), src.target.clone());
                return Ok(v);
            }
            Err(ClientError::Server { code, .. }) if code == "not_found" => continue,
            Err(ClientError::Server { code, message }) => return Err(format!("{}: {code}: {message}", src.target)),
            Err(e) => {
                open.remove(&src.target);
                why = format!("{}: {e}", src.target);
            }
        }
    }
    Err(why)
}

/// Ask the fleet to do `ask` for each of `items` on the box that holds its
/// region ([`ask_holder`]); the first refusal ends it. `Err` carries why, and
/// how many items were done.
fn ask_holders<T>(
    sources: &[ReplicaSource],
    items: &[T],
    region: impl Fn(&T) -> &str,
    mut ask: impl FnMut(&mut crate::Client, &T) -> std::result::Result<(), ClientError>,
) -> Result<(), (String, usize)> {
    let mut open: HashMap<String, crate::Client> = HashMap::new();
    for (n, item) in items.iter().enumerate() {
        ask_holder(&mut open, sources, region(item), |client| ask(client, item)).map_err(|why| (why, n))?;
    }
    Ok(())
}

/// D169 — a delete that came through the view, for the copies OTHER boxes
/// hold: ask the fleet, box by box, to move `rel_path` in each `(region,
/// hash)` to that region's trash. A box that does not hold the region says
/// `not_found` and the next is asked; a copy already gone is not an error;
/// `conflict` (the file changed) and `forbidden` (no write rights) are. An
/// error leaves whatever was already trashed in the trash — a retry finishes.
pub fn trash_elsewhere(sources: &[ReplicaSource], rel_path: &str, copies: &[(String, String)]) -> Result<(), String> {
    ask_holders(sources, copies, |(region, _)| region.as_str(), |client, (region, hash)| {
        client.trash_path(region, rel_path, hash).map(|_| ())
    })
    .map_err(|(why, _)| why)
}

/// PVOS D168 — `pvfs trash put`: each `(region, rel_path, hash)` to its
/// region's trash on the box that holds it, over one connection per box for
/// the whole list. Unlike a delete through the view (every copy, all or
/// nothing), each item is ONE region's copy and its own answer: `Ok(true)`
/// trashed, `Ok(false)` already gone, `Err` why that box refused (the file
/// changed, no write rights) or that nobody holds the region — and the list
/// goes on.
pub fn trash_each(sources: &[ReplicaSource], items: &[(String, String, String)]) -> Vec<Result<bool, String>> {
    let mut open: HashMap<String, crate::Client> = HashMap::new();
    items
        .iter()
        .map(|(region, rel_path, hash)| ask_holder(&mut open, sources, region, |c| c.trash_path(region, rel_path, hash)))
        .collect()
}

/// D170 — one copy a view rename moves: its region, and for a file the
/// (hash, size) the view showed (`None` = a folder).
pub type RenameCopy = (String, Option<(String, u64)>);

/// D170 — a rename through a view mount, for the copies other boxes hold:
/// each is renamed on the box that catalogues its region. `Err` carries why
/// and how many copies had been renamed, so the caller can put them back.
pub fn rename_elsewhere(
    sources: &[ReplicaSource],
    from: &str,
    to: &str,
    copies: &[RenameCopy],
) -> Result<(), (String, usize)> {
    ask_holders(sources, copies, |(region, _)| region.as_str(), |client, (region, file)| {
        client
            .rename_path(region, from, to, file.as_ref().map(|(h, s)| (h.as_str(), *s)))
            .map(|_| ())
    })
}

/// D170 — an `rmdir` through a view mount, for the regions other boxes
/// hold. `Err` is why; `not_empty` reads "…: not_empty: …".
pub fn rmdir_elsewhere(sources: &[ReplicaSource], rel_path: &str, regions: &[String]) -> Result<(), String> {
    ask_holders(sources, regions, |r| r.as_str(), |client, region| {
        client.remove_dir(region, rel_path).map(|_| ())
    })
    .map_err(|(why, _)| why)
}

/// What [`HashCache::open`] found.
pub enum Opened {
    /// A whole, verified file in the store: read it like any local file,
    /// and tell the cache when the handle closes ([`HashCache::close_local`]).
    Local(PathBuf),
    /// A read-through: ask it for ranges; [`HashFetch::handle_closed`] at
    /// release.
    Stream(Arc<HashFetch>),
}

/// What one pass of the bound did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EvictReport {
    pub removed: usize,
    pub removed_bytes: u64,
    pub kept: usize,
    pub kept_bytes: u64,
}

struct CacheInner {
    data_dir: PathBuf,
    opts: CacheOpts,
    explicit: Option<Vec<ReplicaSource>>,
    fetches: Mutex<HashMap<String, Arc<HashFetch>>>,
    pins: Mutex<HashMap<String, usize>>,
    gate: Gate,
    pool: Mutex<HashMap<String, Vec<crate::Client>>>,
    probes: AtomicU64,
    completed: AtomicU64,
    fetched: AtomicU64,
    /// The box that served last. A scan walks a library directory by
    /// directory, so the next file is most likely on the same box: asking it
    /// first saves a `not_found` round trip per file over the WAN.
    hint: AtomicUsize,
}

impl CacheInner {
    /// The boxes to ask: the given list, else the fleet's announced
    /// endpoints minus this box, in pin order (D130's rule).
    fn sources(&self) -> Vec<ReplicaSource> {
        match &self.explicit {
            Some(s) => s.clone(),
            None => announced_sources(&self.data_dir),
        }
    }

    fn checkout(&self, target: &str) -> Option<crate::Client> {
        self.pool.lock().unwrap().get_mut(target).and_then(Vec::pop)
    }

    fn checkin(&self, target: &str, client: crate::Client) {
        let mut pool = self.pool.lock().unwrap();
        let idle = pool.entry(target.to_string()).or_default();
        if idle.len() < self.opts.streams {
            idle.push(client);
        }
    }

    fn forget(&self, fetch: &Arc<HashFetch>) {
        let mut map = self.fetches.lock().unwrap();
        if map.get(&fetch.hash).is_some_and(|f| Arc::ptr_eq(f, fetch)) {
            map.remove(&fetch.hash);
        }
    }

    /// Stream mode: a file nobody has open and nothing is fetching goes —
    /// its map entry and its partial, under the map's lock, so an open
    /// either took it up first (and it stays) or starts a new one after.
    /// A fetch already replaced in the map leaves the path to its successor.
    fn drop_idle_stream(&self, fetch: &Arc<HashFetch>) {
        let mut map = self.fetches.lock().unwrap();
        let st = fetch.st.lock().unwrap();
        if st.handles > 0 || st.worker {
            return;
        }
        if map.get(&fetch.hash).is_some_and(|f| Arc::ptr_eq(f, fetch)) {
            map.remove(&fetch.hash);
            let _ = std::fs::remove_file(&fetch.part);
        }
    }

    fn by_hash_dir(&self) -> Option<PathBuf> {
        pvfs_core::sync::sync_store_dir(&self.data_dir).ok().map(|d| d.join("by-hash"))
    }

    /// Every entry under `by-hash/`: (path, hash, is_partial, allocated bytes, last read).
    fn entries(&self) -> Vec<(PathBuf, String, bool, u64, SystemTime)> {
        let mut out = Vec::new();
        let Some(root) = self.by_hash_dir() else { return out };
        let Ok(shards) = std::fs::read_dir(&root) else { return out };
        for shard in shards.flatten() {
            let Ok(files) = std::fs::read_dir(shard.path()) else { continue };
            for f in files.flatten() {
                let path = f.path();
                let Ok(meta) = f.metadata() else { continue };
                if !meta.is_file() {
                    continue;
                }
                let name = f.file_name().to_string_lossy().into_owned();
                let (hash, partial) = match name.strip_suffix(".partial") {
                    Some(h) => (h.to_string(), true),
                    None => (name, false),
                };
                #[cfg(unix)]
                let bytes = std::os::unix::fs::MetadataExt::blocks(&meta) * 512;
                #[cfg(not(unix))]
                let bytes = meta.len();
                out.push((path, hash, partial, bytes, meta.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
            }
        }
        out
    }

    fn evict(&self) -> EvictReport {
        let mut report = EvictReport::default();
        let mut entries = self.entries();
        entries.sort_by_key(|e| e.4);
        let now = SystemTime::now();
        let mut total: u64 = entries.iter().map(|e| e.3).sum();
        for (path, hash, partial, bytes, read) in entries {
            let old = now.duration_since(read).is_ok_and(|age| age > self.opts.max_age);
            if !(old || total > self.opts.max_bytes) {
                report.kept += 1;
                report.kept_bytes += bytes;
                continue;
            }
            // Busy is judged and the entry dropped under one lock, so an
            // open cannot take up a fetch whose partial is being removed.
            let mut map = self.fetches.lock().unwrap();
            let busy = self.pins.lock().unwrap().get(&hash).is_some_and(|n| *n > 0)
                || map.get(&hash).is_some_and(|f| {
                    let st = f.st.lock().unwrap();
                    st.handles > 0 || st.worker
                });
            if busy {
                report.kept += 1;
                report.kept_bytes += bytes;
                continue;
            }
            if partial {
                map.remove(&hash);
            }
            if std::fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(bytes);
                report.removed += 1;
                report.removed_bytes += bytes;
            }
        }
        report
    }
}

/// The view mount's read-through cache over one box's hash store.
#[derive(Clone)]
pub struct HashCache {
    inner: Arc<CacheInner>,
}

impl HashCache {
    /// The cache over `data_dir`'s hash store, asking the fleet's announced
    /// endpoints. Sweeps the partials a previous mount left and applies the
    /// bound once.
    pub fn new(data_dir: &Path, opts: CacheOpts) -> HashCache {
        HashCache::build(data_dir, opts, None)
    }

    /// [`HashCache::new`] asking exactly `sources` (tests, the lab).
    pub fn with_sources(data_dir: &Path, opts: CacheOpts, sources: Vec<ReplicaSource>) -> HashCache {
        HashCache::build(data_dir, opts, Some(sources))
    }

    fn build(data_dir: &Path, opts: CacheOpts, explicit: Option<Vec<ReplicaSource>>) -> HashCache {
        let inner = Arc::new(CacheInner {
            data_dir: data_dir.to_path_buf(),
            gate: Gate::new(opts.streams),
            opts,
            explicit,
            fetches: Mutex::new(HashMap::new()),
            pins: Mutex::new(HashMap::new()),
            pool: Mutex::new(HashMap::new()),
            probes: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            fetched: AtomicU64::new(0),
            hint: AtomicUsize::new(0),
        });
        for (path, _, partial, _, _) in inner.entries() {
            if partial {
                let _ = std::fs::remove_file(path);
            }
        }
        inner.evict();
        HashCache { inner }
    }

    pub fn opts(&self) -> &CacheOpts {
        &self.inner.opts
    }

    /// Open `hash` (`size` bytes) for reading: the kept file if the store
    /// has it, else its read-through — the same one for every handle on it.
    pub fn open(&self, hash: &str, size: u64) -> Result<Opened, String> {
        let final_path = pvfs_core::sync::hash_store_path(&self.inner.data_dir, hash).map_err(|e| e.to_string())?;
        let mut map = self.inner.fetches.lock().unwrap();
        if final_path.is_file() {
            touch(&final_path);
            *self.inner.pins.lock().unwrap().entry(hash.to_string()).or_insert(0) += 1;
            return Ok(Opened::Local(final_path));
        }
        if map.get(hash).is_some_and(|f| f.failed()) {
            // A failed fetch must not stick: this open tries again.
            map.remove(hash);
        }
        let fetch = match map.get(hash) {
            Some(f) => Arc::clone(f),
            None => {
                let n = (size.div_ceil(self.inner.opts.piece)).max(1) as usize;
                let f = Arc::new(HashFetch {
                    hash: hash.to_string(),
                    size,
                    part: final_path.with_extension("partial"),
                    final_path,
                    cache: Arc::downgrade(&self.inner),
                    opts: self.inner.opts.clone(),
                    st: Mutex::new(FetchSt {
                        pieces: Pieces::new(if size == 0 { 0 } else { n }),
                        demands: Vec::new(),
                        next_demand: 0,
                        handles: 0,
                        last_close: None,
                        completing: size == 0,
                        seq_end: 0,
                        seq_bytes: 0,
                        worker: false,
                        finished: None,
                        fetched: 0,
                        fail_gen: 0,
                        last_err: String::new(),
                        last_fail: None,
                        cursors: Vec::new(),
                        prefetch: None,
                        swept: 0,
                    }),
                    cv: Condvar::new(),
                });
                self.inner.probes.fetch_add(1, Ordering::Relaxed);
                map.insert(hash.to_string(), Arc::clone(&f));
                f
            }
        };
        fetch.handle_opened();
        Ok(Opened::Stream(fetch))
    }

    /// A handle on a kept file closed.
    pub fn close_local(&self, hash: &str) {
        let mut pins = self.inner.pins.lock().unwrap();
        if let Some(n) = pins.get_mut(hash) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                pins.remove(hash);
            }
        }
    }

    /// Apply the bound now.
    pub fn evict(&self) -> EvictReport {
        self.inner.evict()
    }

    /// Apply the bound every `janitor_every` for as long as the cache lives,
    /// saying what the cache did when it did anything.
    pub fn start_janitor(&self) {
        let weak = Arc::downgrade(&self.inner);
        std::thread::spawn(move || {
            let mut said = (0u64, 0u64, 0u64);
            let mut slept = Duration::ZERO;
            loop {
                std::thread::sleep(Duration::from_secs(1));
                slept += Duration::from_secs(1);
                let Some(inner) = weak.upgrade() else { return };
                if slept < inner.opts.janitor_every {
                    continue;
                }
                slept = Duration::ZERO;
                let r = inner.evict();
                let now = (
                    inner.probes.load(Ordering::Relaxed),
                    inner.completed.load(Ordering::Relaxed),
                    inner.fetched.load(Ordering::Relaxed),
                );
                if now != said || r.removed > 0 {
                    eprintln!(
                        "mount: read-through cache — {} file(s) opened through, {} kept whole, {} bytes fetched; holding {} entries, {} bytes; evicted {} ({} bytes)",
                        now.0, now.1, now.2, r.kept, r.kept_bytes, r.removed, r.removed_bytes
                    );
                    said = now;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_piece_map_counts_and_finds() {
        let mut p = Pieces::new(130);
        assert!(!p.all() && p.first_missing(0, 129) == Some(0));
        for i in 0..130 {
            p.set(i);
            p.set(i); // twice is once
        }
        assert!(p.all() && p.have == 130 && p.first_missing(0, 129).is_none());
        p.clear();
        p.set(64);
        assert_eq!(p.first_missing(64, 70), Some(65));
        assert_eq!(p.first_missing(64, 64), None);
        assert!(!p.get(500), "out of range is absent, not a panic");
    }

    #[test]
    fn a_waiting_read_gets_the_network_before_a_background_burst() {
        let gate = Arc::new(Gate::new(1));
        let held = gate.acquire(false);
        let order = Arc::new(Mutex::new(Vec::new()));
        let bg = {
            let (gate, order) = (Arc::clone(&gate), Arc::clone(&order));
            std::thread::spawn(move || {
                let _p = gate.acquire(false);
                order.lock().unwrap().push("background");
            })
        };
        // The background waiter is parked first; the demand arrives later
        // and must still go first.
        std::thread::sleep(Duration::from_millis(100));
        let dm = {
            let (gate, order) = (Arc::clone(&gate), Arc::clone(&order));
            std::thread::spawn(move || {
                let _p = gate.acquire(true);
                order.lock().unwrap().push("demand");
                std::thread::sleep(Duration::from_millis(50));
            })
        };
        std::thread::sleep(Duration::from_millis(100));
        drop(held);
        dm.join().unwrap();
        bg.join().unwrap();
        assert_eq!(*order.lock().unwrap(), vec!["demand", "background"]);
    }

    fn st(n: usize) -> FetchSt {
        FetchSt {
            pieces: Pieces::new(n),
            demands: Vec::new(),
            next_demand: 0,
            handles: 1,
            last_close: None,
            completing: false,
            seq_end: 0,
            seq_bytes: 0,
            worker: true,
            finished: None,
            fetched: 0,
            fail_gen: 0,
            last_err: String::new(),
            last_fail: None,
            cursors: Vec::new(),
            prefetch: None,
            swept: 0,
        }
    }

    #[test]
    fn the_worker_fetches_what_was_asked_then_ahead_then_the_rest() {
        let o = CacheOpts {
            piece: 10,
            burst: 30,
            ..CacheOpts::default()
        };
        let mut s = st(100);
        // a probe of the tail: that piece and nothing more
        s.demands.push(Demand { id: 0, first: 99, last: 99, ahead: 0 });
        assert!(matches!(next_job(&s, &o), Some(Job::Fetch { first: 99, end: 100, demand: true })));
        s.pieces.set(99);
        assert!(next_job(&s, &o).is_none(), "an open handle with nothing asked: wait");
        // a sequential reader: what it asked plus its readahead, stopping
        // at a piece that is already there
        s.demands = vec![Demand { id: 1, first: 4, last: 5, ahead: 4 }];
        s.pieces.set(8);
        assert!(matches!(next_job(&s, &o), Some(Job::Fetch { first: 4, end: 8, demand: true })));
        // completing: the rest, a burst at a time, from the first gap
        s.demands.clear();
        s.completing = true;
        assert!(matches!(next_job(&s, &o), Some(Job::Fetch { first: 0, end: 3, demand: false })));
        // closed: a probe's fetch ends; a completing one runs its grace
        s.completing = false;
        s.handles = 0;
        s.last_close = Some(Instant::now());
        assert!(matches!(next_job(&s, &o), Some(Job::Exit)));
        s.completing = true;
        assert!(matches!(next_job(&s, &o), Some(Job::Fetch { demand: false, .. })));
        s.last_close = Some(Instant::now() - o.grace - Duration::from_secs(1));
        assert!(matches!(next_job(&s, &o), Some(Job::Exit)), "2 of 100 pieces after the grace: stop");
        for i in 0..75 {
            s.pieces.set(i);
        }
        assert!(matches!(next_job(&s, &o), Some(Job::Fetch { demand: false, .. })), "three quarters through: finish");
        for i in 0..100 {
            s.pieces.set(i);
        }
        assert!(matches!(next_job(&s, &o), Some(Job::Verify)));
    }

    fn entry(cache: &HashCache, tag: u8, bytes: usize, age: Duration, partial: bool) -> (String, PathBuf) {
        let hash = format!("{tag:02x}").repeat(32);
        let mut p = pvfs_core::sync::hash_store_path(&cache.inner.data_dir, &hash).unwrap();
        if partial {
            p = p.with_extension("partial");
        }
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![tag; bytes]).unwrap();
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.sync_all().unwrap(); // allocated blocks are what the bound counts
        f.set_modified(SystemTime::now() - age).unwrap();
        (hash, p)
    }

    #[test]
    fn the_bound_takes_the_old_then_the_least_recently_read_never_an_open_one() {
        let dir = tempfile::tempdir().unwrap();
        let one = 256 * 1024;
        let probe = HashCache::with_sources(dir.path(), CacheOpts::default(), Vec::new());
        let (_, p) = entry(&probe, 0xee, one, Duration::ZERO, false);
        let allocated = probe.inner.entries()[0].3;
        std::fs::remove_file(p).unwrap();

        let opts = CacheOpts {
            max_bytes: allocated * 2 + allocated / 2,
            max_age: Duration::from_secs(3600),
            ..CacheOpts::default()
        };
        let cache = HashCache::with_sources(dir.path(), opts.clone(), Vec::new());
        let (_, stale) = entry(&cache, 0x01, one, Duration::from_secs(7200), false);
        let (h_old, old) = entry(&cache, 0x02, one, Duration::from_secs(600), false);
        let (_, mid) = entry(&cache, 0x03, one, Duration::from_secs(300), false);
        let (_, new) = entry(&cache, 0x04, one, Duration::from_secs(60), false);

        // `old` is open: the age takes `stale`, and the cap — still one
        // over — takes `mid`, the least recently read that nobody holds.
        assert!(matches!(cache.open(&h_old, one as u64).unwrap(), Opened::Local(_)));
        // (the open touched it; put its age back so only the pin protects it)
        std::fs::File::options().write(true).open(&old).unwrap().set_modified(SystemTime::now() - Duration::from_secs(600)).unwrap();
        let r = cache.evict();
        assert_eq!(r.removed, 2, "{r:?}");
        assert!(!stale.exists() && old.exists() && !mid.exists() && new.exists());
        cache.close_local(&h_old);

        // A partial a previous mount left is swept when the cache is made.
        let (_, part) = entry(&cache, 0x05, one, Duration::ZERO, true);
        let again = HashCache::with_sources(dir.path(), opts, Vec::new());
        assert!(!part.exists());
        assert_eq!(again.evict().removed, 0, "two entries, under the cap");
    }
}
