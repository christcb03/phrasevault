//! PVOS D194 — a fetched catalogue snapshot is installed as the difference
//! between the rows held and the manifest: a head bump writes only what
//! changed, the rows end exactly as a full install would leave them, and a
//! commit from another connection between the read and the write is seen.

use std::collections::BTreeMap;

use pvfs_core::acl::Principal;
use pvfs_core::{crypto, identity, Engine, NodeSpec, RegionEntry, SnapshotInstall, TYPE_FOLDER};

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec {
            node_type: TYPE_FOLDER.into(),
            label: label.into(),
            payload: Vec::new(),
            is_temp: false,
            creation_nonce: None,
        },
    )
    .unwrap()
}

fn row(rel: &str, kind: &str, size: u64, mtime: u64, hash: Option<&str>, quality: Option<&str>) -> RegionEntry {
    RegionEntry {
        rel_path: rel.into(),
        kind: kind.into(),
        size_bytes: size,
        mtime_ms: mtime,
        changed_ms: mtime,
        content_hash: hash.map(|h| h.repeat(32)),
        quality: quality.map(|q| q.into()),
        seen_at: 0,
    }
}

/// The region's box (another key) publishes `hash` as its head at `seq`.
fn attest(e: &mut Engine, key: &identity::SigningKey, region: &str, seq: u64, hash: &str) {
    let pubkey = crypto::pubkey_bytes(key);
    let prep = e
        .prepare_commit_region_head(&pubkey, &region.to_string(), seq, hash)
        .unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
}

/// A forest with one catalogue region another box holds, nothing fetched.
struct Far {
    _tmp: tempfile::TempDir,
    e: Engine,
    key: identity::SigningKey,
    far: String,
}

fn far_region() -> Far {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let holder = crypto::pubkey_bytes(&key);
    e.authorize_member(&mn, &holder).unwrap();
    let far = folder(&mut e, &root, "Far");
    e.region_mark_as(&far, "catalogue", Some(&Principal::Key(holder))).unwrap();
    Far { _tmp: tmp, e, key, far }
}

impl Far {
    /// Attest `rows` as head `seq`; the manifest's bytes.
    fn attest(&mut self, seq: u64, rows: &[RegionEntry]) -> Vec<u8> {
        let bytes = Engine::region_manifest_bytes(&self.far, seq, rows);
        let hash = blake3::hash(&bytes).to_hex().to_string();
        attest(&mut self.e, &self.key, &self.far, seq, &hash);
        bytes
    }

    /// Attest `rows` as head `seq`, then install it.
    fn head(&mut self, seq: u64, rows: &[RegionEntry]) -> SnapshotInstall {
        let bytes = self.attest(seq, rows);
        self.e.install_region_snapshot_delta(&self.far, seq, &bytes, "test").unwrap()
    }

    fn index(&self) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(self.e.data_dir().join("index.db")).unwrap();
        c.busy_timeout(std::time::Duration::from_secs(15)).unwrap();
        c
    }
}

/// Every column an install writes, as `region_entries` holds it (a fetched
/// row's `changed_ms` is its mtime); `seen_at` apart.
type Cols = (String, String, u64, u64, u64, Option<String>, Option<String>);

fn cols(r: &RegionEntry) -> Cols {
    (
        r.rel_path.clone(),
        r.kind.clone(),
        r.size_bytes,
        r.mtime_ms,
        r.changed_ms,
        r.content_hash.clone(),
        r.quality.clone(),
    )
}

/// What a full install of `rows` leaves, in `region_entries` order.
fn expected(rows: &[RegionEntry]) -> Vec<Cols> {
    let mut v: Vec<Cols> = rows
        .iter()
        .map(|r| {
            let mut c = cols(r);
            c.4 = r.mtime_ms;
            c
        })
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

fn held(e: &Engine, region: &str) -> Vec<Cols> {
    e.region_entries(&region.to_string()).unwrap().iter().map(cols).collect()
}

#[test]
fn a_head_bump_writes_only_what_changed() {
    let mut f = far_region();
    let t = 1_700_000_000_000;
    let head1 = vec![
        row("Movies", "dir", 0, 0, None, None),
        row("Movies/a.mkv", "file", 100, t, Some("aa"), None),
        row("Movies/b.mkv", "file", 200, t, Some("bb"), Some("q1")),
        row("Movies/c", "file", 300, t, None, None),
        row("Movies/d.mkv", "file", 400, t, Some("dd"), None),
        row("Movies/e.mkv", "file", 500, t, Some("ee"), Some("q3")),
    ];
    assert_eq!(f.head(1, &head1), SnapshotInstall { rows: 6, added: 6, changed: 0, removed: 0 });
    let first = f.e.region_entries(&f.far).unwrap();
    let s1 = first[0].seen_at;
    assert!(first.iter().all(|r| r.seen_at == s1), "one install, one stamp");
    std::thread::sleep(std::time::Duration::from_millis(5));

    let head2 = vec![
        row("Movies", "dir", 0, 0, None, None),
        row("Movies/a.mkv", "file", 101, t + 1, Some("a2"), None), // size, mtime, hash
        row("Movies/b.mkv", "file", 200, t, Some("bb"), Some("q2")), // quality only
        row("Movies/c", "dir", 0, 0, None, None),                    // a file became a folder
        row("Movies/e.mkv", "file", 500, t, Some("ee"), Some("q3")), // untouched
        row("Movies/f.mkv", "file", 600, t, Some("ff"), None),       // new; d.mkv gone
    ];
    assert_eq!(f.head(2, &head2), SnapshotInstall { rows: 6, added: 1, changed: 3, removed: 1 });
    assert_eq!(held(&f.e, &f.far), expected(&head2));
    let after = f.e.region_entries(&f.far).unwrap();
    for r in &after {
        let untouched = r.rel_path == "Movies" || r.rel_path == "Movies/e.mkv";
        if untouched {
            assert_eq!(r.seen_at, s1, "{} was not rewritten", r.rel_path);
        } else {
            assert!(r.seen_at > s1, "{} was written by head 2", r.rel_path);
        }
    }

    // The same content under the next head writes nothing but the record.
    assert_eq!(f.head(3, &head2), SnapshotInstall { rows: 6, added: 0, changed: 0, removed: 0 });
    let st = f.e.catalogue_status().unwrap().into_iter().find(|s| s.region == f.far).unwrap();
    assert_eq!((st.held_seq, st.stale, st.entries), (Some(3), false, 6));
    f.e.close().unwrap();
}

/// xorshift64: the same history on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn path(&mut self) -> String {
        let show = self.below(40);
        match self.below(20) {
            0 => format!("Show {show}/tab\there.mkv"),
            1 => format!("Show {show}/new\nline.mkv"),
            2 => format!("Show {show}/back\\slash.mkv"),
            3 => format!("Fïlm {show}/é.mkv"),
            4 => format!("Show {show}"),
            _ => format!("Show {show}/S01E{:02}.mkv", self.below(30)),
        }
    }

    fn entry(&mut self, path: String) -> RegionEntry {
        let dir = self.below(8) == 0;
        let mtime = 1_700_000_000_000 + self.below(1_000_000_000);
        RegionEntry {
            rel_path: path,
            kind: if dir { "dir" } else { "file" }.into(),
            size_bytes: if dir { 0 } else { self.below(1 << 40) },
            mtime_ms: mtime,
            changed_ms: mtime,
            content_hash: (!dir && self.below(5) != 0).then(|| {
                format!("{:016x}{:016x}{:016x}{:016x}", self.next(), self.next(), self.next(), self.next())
            }),
            quality: (self.below(3) == 0).then(|| format!("q{}", self.below(5))),
            seen_at: 0,
        }
    }

    fn pick(&mut self, rows: &BTreeMap<String, RegionEntry>) -> Option<String> {
        if rows.is_empty() {
            return None;
        }
        rows.keys().nth(self.below(rows.len() as u64) as usize).cloned()
    }
}

/// What turning `old` into `new` takes, by path.
fn true_delta(old: &BTreeMap<String, RegionEntry>, new: &BTreeMap<String, RegionEntry>) -> SnapshotInstall {
    SnapshotInstall {
        rows: new.len(),
        added: new.keys().filter(|k| !old.contains_key(*k)).count(),
        changed: new
            .iter()
            .filter(|(k, r)| old.get(*k).is_some_and(|o| cols(o) != cols(r)))
            .count(),
        removed: old.keys().filter(|k| !new.contains_key(*k)).count(),
    }
}

#[test]
fn every_history_ends_where_a_full_install_would() {
    let mut f = far_region();
    let mut rng = Rng(0x00d1_94ca_7a1a_de17);
    let mut now: BTreeMap<String, RegionEntry> = BTreeMap::new();
    for _ in 0..300 {
        let p = rng.path();
        let r = rng.entry(p.clone());
        now.insert(p, r);
    }
    let mut prev: BTreeMap<String, RegionEntry> = BTreeMap::new();
    for seq in 1..=30u64 {
        if seq > 1 {
            for _ in 0..rng.below(14) {
                match rng.below(6) {
                    0 => {
                        let p = rng.path();
                        let r = rng.entry(p.clone());
                        now.insert(p, r);
                    }
                    1 => {
                        if let Some(k) = rng.pick(&now) {
                            now.remove(&k);
                        }
                    }
                    2 => {
                        // a rename: same attributes, another path
                        if let Some(k) = rng.pick(&now) {
                            let mut r = now.remove(&k).unwrap();
                            r.rel_path = rng.path();
                            now.insert(r.rel_path.clone(), r);
                        }
                    }
                    3 => {
                        if let Some(k) = rng.pick(&now) {
                            let r = now.get_mut(&k).unwrap();
                            r.size_bytes += 1;
                            r.mtime_ms += 1_000;
                            r.changed_ms = r.mtime_ms;
                        }
                    }
                    4 => {
                        if let Some(k) = rng.pick(&now) {
                            let q = rng.below(4);
                            let r = now.get_mut(&k).unwrap();
                            if q == 0 {
                                r.quality = None;
                            } else {
                                r.quality = Some(format!("q{q}"));
                                r.content_hash = r.content_hash.as_ref().map(|h| h.chars().rev().collect());
                            }
                        }
                    }
                    _ => {
                        if let Some(k) = rng.pick(&now) {
                            let r = now.get_mut(&k).unwrap();
                            r.kind = if r.kind == "dir" { "file" } else { "dir" }.into();
                        }
                    }
                }
            }
        }
        let rows: Vec<RegionEntry> = now.values().cloned().collect();
        let got = f.head(seq, &rows);
        assert_eq!(got, true_delta(&prev, &now), "head {seq}");
        assert_eq!(held(&f.e, &f.far), expected(&rows), "head {seq}: the rows are the manifest's");
        prev = now.clone();
    }
    f.e.close().unwrap();
}

/// Run `f` while another connection keeps asking for the write lock
/// (`BEGIN IMMEDIATE`, no wait); the longest stretch it was refused is how
/// long `f` held the lock against the daemon's other writers.
fn while_probing<T>(index: &std::path::Path, f: impl FnOnce() -> T) -> (T, std::time::Duration) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let probe = {
        let (stop, index) = (stop.clone(), index.to_path_buf());
        std::thread::spawn(move || {
            let c = rusqlite::Connection::open(index).unwrap();
            c.busy_timeout(Duration::ZERO).unwrap();
            let (mut longest, mut since) = (Duration::ZERO, None::<Instant>);
            while !stop.load(Ordering::SeqCst) {
                if c.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").is_ok() {
                    if let Some(s) = since.take() {
                        longest = longest.max(s.elapsed());
                    }
                } else {
                    since.get_or_insert_with(Instant::now);
                }
                std::thread::sleep(Duration::from_micros(500));
            }
            since.map_or(longest, |s| longest.max(s.elapsed()))
        })
    };
    std::thread::sleep(Duration::from_millis(20));
    let out = f();
    stop.store(true, Ordering::SeqCst);
    (out, probe.join().unwrap())
}

#[test]
fn thirty_thousand_rows_two_changes_two_writes() {
    let mut f = far_region();
    // Every write to region_entries, counted by the database itself.
    let c = f.index();
    c.execute_batch(
        "CREATE TABLE d194_writes (n INTEGER NOT NULL);
         INSERT INTO d194_writes VALUES (0);
         CREATE TRIGGER d194_ins AFTER INSERT ON region_entries BEGIN UPDATE d194_writes SET n = n + 1; END;
         CREATE TRIGGER d194_upd AFTER UPDATE ON region_entries BEGIN UPDATE d194_writes SET n = n + 1; END;
         CREATE TRIGGER d194_del AFTER DELETE ON region_entries BEGIN UPDATE d194_writes SET n = n + 1; END;",
    )
    .unwrap();
    let writes = |c: &rusqlite::Connection| -> i64 {
        let n = c.query_row("SELECT n FROM d194_writes", [], |r| r.get(0)).unwrap();
        c.execute("UPDATE d194_writes SET n = 0", []).unwrap();
        n
    };
    let t = 1_700_000_000_000;
    let mut rows: Vec<RegionEntry> = (0..30_000)
        .map(|i| row(&format!("TV/Show {:04}/S01E{:02}.mkv", i / 20, i % 20), "file", 1_000 + i, t, Some("ab"), None))
        .collect();
    rows.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    let index = f.e.data_dir().join("index.db");
    let bytes = f.attest(1, &rows);
    let started = std::time::Instant::now();
    let (got, first_lock) =
        while_probing(&index, || f.e.install_region_snapshot_delta(&f.far, 1, &bytes, "test").unwrap());
    let first = started.elapsed();
    assert_eq!(got.added, 30_000);
    assert_eq!(writes(&c), 30_000, "the trigger sees an install");

    // mediabox-local on 2026-09-26: two rows moved between heads.
    rows[7].size_bytes += 1;
    rows[7].mtime_ms += 1;
    rows[7].changed_ms = rows[7].mtime_ms;
    rows.remove(20_000);
    let bytes = f.attest(2, &rows);
    let started = std::time::Instant::now();
    let (got, second_lock) =
        while_probing(&index, || f.e.install_region_snapshot_delta(&f.far, 2, &bytes, "test").unwrap());
    let second = started.elapsed();
    assert_eq!(got, SnapshotInstall { rows: 29_999, added: 0, changed: 1, removed: 1 });
    assert_eq!(writes(&c), 2, "a two-row bump writes two rows, not every row twice");
    assert_eq!(held(&f.e, &f.far), expected(&rows));
    eprintln!(
        "d194: 30,000 new rows: install {first:?}, write lock held {first_lock:?}; \
         a two-row bump: install {second:?}, write lock held {second_lock:?}"
    );
    f.e.close().unwrap();
}

#[test]
fn a_commit_between_the_read_and_the_lock_is_seen() {
    let mut f = far_region();
    let t = 1_700_000_000_000;
    let head1 = vec![
        row("A.mkv", "file", 1, t, Some("aa"), None),
        row("B.mkv", "file", 2, t, Some("bb"), None),
        row("C.mkv", "file", 3, t, Some("cc"), None),
    ];
    f.head(1, &head1);
    let mut head2 = head1.clone();
    head2.push(row("D.mkv", "file", 4, t, Some("dd"), None));
    let bytes = Engine::region_manifest_bytes(&f.far, 2, &head2);
    let hash = blake3::hash(&bytes).to_hex().to_string();
    attest(&mut f.e, &f.key, &f.far, 2, &hash);

    // After the install has read A, B and C (so its delta is "add D"),
    // another connection commits a stray row and changes B.
    let other = f.index();
    let far = f.far.clone();
    let got = f
        .e
        .install_region_snapshot_with(&f.far, 2, &bytes, "test", || {
            other
                .execute(
                    "INSERT INTO region_entries
                       (region_id, rel_path, kind, size_bytes, mtime_ms, changed_ms, content_hash, quality, seen_at)
                     VALUES (?1, 'Z/stray.mkv', 'file', 9, 9, 9, NULL, NULL, 9)",
                    [&far],
                )
                .unwrap();
            other
                .execute(
                    "UPDATE region_entries SET size_bytes = 999 WHERE region_id = ?1 AND rel_path = 'B.mkv'",
                    [&far],
                )
                .unwrap();
        })
        .unwrap();
    assert_eq!(held(&f.e, &f.far), expected(&head2), "the stray row gone, B put back, D added");
    assert_eq!(got, SnapshotInstall { rows: 4, added: 1, changed: 1, removed: 1 }, "the delta of the re-read");
    f.e.close().unwrap();
}

#[test]
fn a_manifest_listing_a_path_twice_is_refused() {
    let mut f = far_region();
    let t = 1_700_000_000_000;
    let head1 = vec![row("A.mkv", "file", 1, t, Some("aa"), None), row("B.mkv", "file", 2, t, Some("bb"), None)];
    f.head(1, &head1);
    let twice = vec![
        row("A.mkv", "file", 1, t, Some("aa"), None),
        row("B.mkv", "file", 2, t, Some("bb"), None),
        row("B.mkv", "file", 3, t, Some("b2"), None),
    ];
    let bytes = Engine::region_manifest_bytes(&f.far, 2, &twice);
    let hash = blake3::hash(&bytes).to_hex().to_string();
    attest(&mut f.e, &f.key, &f.far, 2, &hash);
    let err = f.e.install_region_snapshot(&f.far, 2, &bytes, "test").unwrap_err();
    assert!(err.to_string().contains("lists B.mkv twice"), "{err}");
    assert_eq!(held(&f.e, &f.far), expected(&head1), "nothing written");
    let st = f.e.catalogue_status().unwrap().into_iter().find(|s| s.region == f.far).unwrap();
    assert_eq!((st.held_seq, st.stale), (Some(1), true));
    f.e.close().unwrap();
}
