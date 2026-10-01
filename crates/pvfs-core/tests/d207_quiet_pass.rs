//! PVOS D207 — a quiet catalogue pass writes nothing (D199 built it; this
//! proves it on the daemon's own path, for every kind of change), and a
//! pass says how far it has got while it runs.
//!
//! 1. Through the daemon's stepped watch (`scan_catalogues` on a
//!    `SharedDb`): a first pass writes every row; a quiet pass writes none;
//!    a new, a changed, a touched (mtime only) and a removed file, a new and
//!    a removed folder are exactly the rows written — and the rows equal a
//!    fresh engine scan of the same tree.
//! 2. A pass given a `JobProgress` reports its phase and its files while it
//!    hashes, and ends with every file and byte counted.

use std::sync::{Arc, Mutex};

use pvfs_core::{BindSpec, Engine, HashPolicy, JobProgress, NodeSpec, SharedDb, Writer, TYPE_FOLDER};

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec { node_type: TYPE_FOLDER.into(), label: label.into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
    )
    .unwrap()
}

/// A catalogue region bound on `media`, which holds 4 shows × 10 episodes.
fn media_region(e: &mut Engine, media: &std::path::Path) -> String {
    for i in 0..40 {
        let d = media.join(format!("Show {}", i % 4));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("e{i:02}.mkv")), format!("episode {i}")).unwrap();
    }
    let root = e.identity.root_node_id.clone();
    let local = folder(e, &root, "Local");
    e.region_mark_as(&local, "catalogue", None).unwrap();
    e.bind_folder(
        &local,
        BindSpec {
            source_uri: format!("file://{}", media.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    local
}

/// What reaches `region_entries`, in order, as `put <path>` / `del <path>`
/// (a trigger per kind of write, on a connection of the test's own).
fn journal(data: &std::path::Path) -> rusqlite::Connection {
    let c = rusqlite::Connection::open(data.join("index.db")).unwrap();
    c.busy_timeout(std::time::Duration::from_secs(15)).unwrap();
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS d207_ops (n INTEGER PRIMARY KEY AUTOINCREMENT, op TEXT NOT NULL);
         CREATE TRIGGER IF NOT EXISTS d207_ins AFTER INSERT ON region_entries BEGIN INSERT INTO d207_ops (op) VALUES ('put ' || NEW.rel_path); END;
         CREATE TRIGGER IF NOT EXISTS d207_upd AFTER UPDATE ON region_entries BEGIN INSERT INTO d207_ops (op) VALUES ('put ' || NEW.rel_path); END;
         CREATE TRIGGER IF NOT EXISTS d207_del AFTER DELETE ON region_entries BEGIN INSERT INTO d207_ops (op) VALUES ('del ' || OLD.rel_path); END;",
    )
    .unwrap();
    c
}

fn ops(c: &rusqlite::Connection) -> Vec<String> {
    let mut s = c.prepare("SELECT op FROM d207_ops ORDER BY n").unwrap();
    let mut v = s.query_map([], |r| r.get(0)).unwrap().collect::<Result<Vec<String>, _>>().unwrap();
    c.execute("DELETE FROM d207_ops", []).unwrap();
    v.sort();
    v
}

fn rows_of(e: &Engine, region: &str) -> Vec<(String, String, u64, u64, Option<String>)> {
    let mut v: Vec<_> = e
        .region_entries(&region.to_string())
        .unwrap()
        .into_iter()
        .map(|r| (r.rel_path, r.kind, r.size_bytes, r.mtime_ms, r.content_hash))
        .collect();
    v.sort();
    v
}

/// One pass of the daemon's watch over `writer`: (added, changed, removed, unchanged).
fn stepped_pass(writer: &Arc<Writer>, progress: Option<Arc<JobProgress>>) -> (u64, u64, u64, u64) {
    let db = SharedDb::new(Arc::clone(writer), "watch").unwrap();
    let mut ctx = pvfs_core::fs::CatalogueCtx::new(None);
    ctx.progress = progress;
    let r = pvfs_core::fs::scan_catalogues(&db, &mut ctx, None, 0).unwrap();
    let s = &r[0].stats;
    (s.added, s.changed, s.removed, s.unchanged)
}

#[test]
fn the_daemons_pass_writes_exactly_the_rows_that_changed() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, _) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let media = tmp.path().join("media");
    let local = media_region(&mut e, &media);
    let j = journal(e.data_dir());
    let writer = Arc::new(Writer::new(e));

    assert_eq!(stepped_pass(&writer, None).0, 40);
    assert_eq!(ops(&j).len(), 44, "the first pass writes every row: 40 files, 4 folders");

    // Nothing changed: nothing written (every pass used to upsert all 44).
    assert_eq!(stepped_pass(&writer, None), (0, 0, 0, 40));
    assert_eq!(ops(&j), Vec::<String>::new(), "a quiet pass writes no row");
    // And again: still nothing (a pass's own `seen_at` is never what makes a write).
    stepped_pass(&writer, None);
    assert!(ops(&j).is_empty());

    // Every kind of change at once.
    std::fs::write(media.join("Show 0/e40.mkv"), "a new episode").unwrap(); // new
    std::fs::write(media.join("Show 1/e05.mkv"), "episode 5, a better copy").unwrap(); // changed
    let touched = media.join("Show 2/e06.mkv"); // touched: same bytes, a new mtime
    let f = std::fs::File::options().write(true).open(&touched).unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5)).unwrap();
    drop(f);
    std::fs::remove_file(media.join("Show 3/e07.mkv")).unwrap(); // removed
    std::fs::create_dir_all(media.join("Show 4")).unwrap(); // a new (empty) folder
    for i in (3..40).step_by(4) {
        let _ = std::fs::remove_file(media.join(format!("Show 3/e{i:02}.mkv")));
    }
    std::fs::remove_dir_all(media.join("Show 3")).unwrap(); // a removed folder (its sidecars with it)
    let (added, changed, removed, _) = stepped_pass(&writer, None);
    let written = ops(&j);
    let mut want: Vec<String> = vec![
        "put Show 0/e40.mkv".into(),
        "put Show 1/e05.mkv".into(),
        "put Show 2/e06.mkv".into(),
        "put Show 4".into(),
        "del Show 3".into(),
    ];
    want.extend((3..40).step_by(4).map(|i| format!("del Show 3/e{i:02}.mkv")));
    want.sort();
    assert_eq!(written, want, "exactly the changed rows, nothing else");
    assert_eq!(added, 1);
    assert_eq!(changed, 2, "the changed and the touched file");
    assert_eq!(removed, 11, "ten files and their folder");

    // The rows are what a fresh engine scan of the same tree leaves.
    let e = Writer::into_engine(writer).ok().expect("no longer shared");
    let fresh = tempfile::tempdir().unwrap();
    let (mut f, _) = Engine::init(fresh.path().join("forest").as_path()).unwrap();
    let root = f.identity.root_node_id.clone();
    let other = folder(&mut f, &root, "Local");
    f.region_mark_as(&other, "catalogue", None).unwrap();
    f.bind_folder(
        &other,
        BindSpec {
            source_uri: format!("file://{}", media.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    f.scan(None).unwrap();
    assert_eq!(rows_of(&e, &local), rows_of(&f, &other));
}

#[test]
fn a_pass_reports_its_progress_while_it_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, _) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let media = tmp.path().join("media");
    media_region(&mut e, &media);
    let total: u64 = (0..40).map(|i| format!("episode {i}").len() as u64).sum();
    let writer = Arc::new(Writer::new(e));
    let progress = Arc::new(JobProgress::new());

    // Seen from the pass's own thread, before each file is read: the phase,
    // and the files done so far.
    type Seen = Arc<Mutex<Vec<(Option<String>, u64)>>>;
    let seen: Seen = Arc::default();
    let db = SharedDb::new(Arc::clone(&writer), "watch").unwrap();
    let mut ctx = pvfs_core::fs::CatalogueCtx::new(None);
    ctx.progress = Some(Arc::clone(&progress));
    {
        let (p, seen) = (Arc::clone(&progress), Arc::clone(&seen));
        ctx.on_read(Box::new(move |_| {
            let s = p.snapshot().expect("a pass in flight");
            seen.lock().unwrap().push((s.phase, s.files_done));
            None
        }));
    }
    progress.begin_pass();
    pvfs_core::fs::scan_catalogues(&db, &mut ctx, None, 0).unwrap();
    let end = progress.snapshot().unwrap();
    progress.end_pass();
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 40, "every file read once");
    assert!(seen.iter().all(|(phase, _)| phase.as_deref() == Some("hashing")));
    assert_eq!(seen.iter().map(|(_, n)| *n).collect::<Vec<_>>(), (0..40).collect::<Vec<_>>(), "counted file by file");
    assert_eq!((end.files_done, end.bytes_done), (40, total));
    assert!(end.current.is_empty(), "nothing in hand at the end");
    assert_eq!(end.phase.as_deref(), Some("publishing"));

    // A second pass takes every hash from its row: counted done, read never.
    progress.begin_pass();
    let mut ctx = pvfs_core::fs::CatalogueCtx::new(None);
    ctx.progress = Some(Arc::clone(&progress));
    pvfs_core::fs::scan_catalogues(&db, &mut ctx, None, 0).unwrap();
    let end = progress.snapshot().unwrap();
    assert_eq!((end.files_done, end.bytes_done), (40, total));
}
