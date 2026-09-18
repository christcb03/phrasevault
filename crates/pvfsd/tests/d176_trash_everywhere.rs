//! D176 — every box purges its catalogue regions' trash by retention and
//! reports it, whatever jobs it runs.
//!
//! The purge lived only in the `receive` and `resolve` job bodies, which were
//! also the only thing that filled `serve status`'s `trash`. mediabox runs
//! neither: its trash (9.7 GB on 2026-09-18, both disks 98 % full) was never
//! purged, and D148's "a bucket older than retention + 1 day: the purge is
//! not running" could never fire for a box that reported nothing. The job
//! runner now does it itself, asking the daemon's read pool which regions
//! are local — no engine opened, nothing folded.
//!
//! Its own test binary: it sets process-wide environment (the step's
//! interval, the config dir, the startup fold wait).

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pvfs_client::{Client, ServeStatusReply};
use pvfs_core::{crypto, identity, projection, sync, BindSpec, Engine, HashPolicy, NodeSpec, PvfsError, TYPE_FOLDER};
use pvfsd::jobs::JobsState;
use pvfsd::{serve, Daemon};

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

fn bind(e: &mut Engine, node: &str, dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    e.bind_folder(
        &node.to_string(),
        BindSpec {
            source_uri: format!("file://{}", dir.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
}

fn region(e: &mut Engine, label: &str, dir: &Path) -> String {
    let root = e.identity.root_node_id.clone();
    let r = folder(e, &root, label);
    e.region_mark_as(&r, "catalogue", None).unwrap();
    bind(e, &r, dir);
    e.scan_routed(Some(&r), None, 0).unwrap();
    r
}

fn write(dir: &Path, rel: &str, bytes: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

/// A trash bucket `day` (days since the epoch) under `root` holding one file.
fn bucket(root: &Path, day: u64, bytes: usize) -> std::path::PathBuf {
    let b = root.join(".pvfs-trash").join(day.to_string());
    write(&b, "TV/Show/Season 1/ep.mkv", &vec![9u8; bytes]);
    b
}

fn today() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 86_400
}

fn applied_mark(data_dir: &Path) -> (u64, String) {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    projection::applied_get(&conn, "").unwrap()
}

fn set_applied_mark(data_dir: &Path, seq: u64, hash: &str) {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    projection::applied_set(&conn, "", seq, hash).unwrap();
}

/// Ask `serve status` until `done` holds, or fail after `secs`.
fn status_until(c: &mut Client, secs: u64, what: &str, done: impl Fn(&ServeStatusReply) -> bool) -> ServeStatusReply {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let s = c.serve_status_full().unwrap();
        if done(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "{what}: never happened; last trash {:?}", s.trash);
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_box_that_runs_neither_receive_nor_resolve_purges_its_trash_and_reports_it() {
    std::env::set_var("PVFS_TRASH_EVERY_MS", "300");
    // The control open below gives up after a second, not a minute (D173).
    std::env::set_var("PVFS_STARTUP_FOLD_WAIT_MS", "1000");
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());

    // mediabox's shape: two catalogue regions, one at the default retention
    // (7 days) and one declared at 3; and a folder bound the old way, which
    // is not a catalogue region and whose trash is not this purge's.
    let tmp = tempfile::tempdir().unwrap();
    let (local, local2, old) = (tmp.path().join("local"), tmp.path().join("local2"), tmp.path().join("old"));
    write(&local, "TV/Show/Season 1/e1.mkv", b"one");
    write(&local2, "TV/Other/Season 2/e2.mkv", b"two");
    let (mut e, mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let r1 = region(&mut e, "mediabox-local", &local);
    let r2 = region(&mut e, "mediabox-local2", &local2);
    let root = e.identity.root_node_id.clone();
    let plain = folder(&mut e, &root, "Old");
    bind(&mut e, &plain, &old);
    sync::set_region_retention(e.data_dir(), &r2, 3).unwrap();
    let d = today();
    let r1_old = bucket(&local, d - 10, 3_000);
    let r1_new = bucket(&local, d, 2_000);
    let r2_old = bucket(&local2, d - 5, 5_000);
    let r2_new = bucket(&local2, d - 2, 1_000);
    let plain_old = bucket(&old, d - 30, 700);

    let me_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me_key);
    e.authorize_member(&mn, &me_pub).unwrap();
    let data_dir = e.data_dir().to_path_buf();
    // No `serve.jobs` at all: whatever jobs a box runs includes none.
    let daemon = Arc::new(Daemon::new(e));
    let jobs = Arc::new(JobsState::load(data_dir.clone()).unwrap());
    daemon.attach_jobs(Arc::clone(&jobs));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let mut member = Client::connect_signed(&sock, &me_pub, |d| crypto::sign_digest(&me_key, d).unwrap()).unwrap();
    let before = member.serve_status_full().unwrap();
    assert!(before.trash.is_empty(), "premise: nothing purged yet, nothing reported");
    assert!(before.jobs.iter().all(|j| j.state == "disabled"), "premise: no job runs here: {:?}", before.jobs);

    // The step opens no engine. Put the cache BEHIND the log (a fold is due
    // at the next open) and hold the fold lock as another process would, and
    // the daemon's writer too (D174's technique): an open could not succeed,
    // and a fold would move the mark.
    let (seq, hash) = applied_mark(&data_dir);
    assert!(seq > 0, "premise: the cache had folded the log");
    set_applied_mark(&data_dir, 0, "");
    let fold_lock = projection::hold_fold_lock_for_test(&data_dir).expect("the fold lock, as another process holds it");
    let control = Engine::open(&data_dir);
    assert!(
        matches!(control, Err(PvfsError::Busy { .. })),
        "premise: in this state an open must fold: {:?}",
        control.map(|_| ())
    );
    let release = Arc::new(AtomicBool::new(false));
    let writer = {
        let (d, release) = (Arc::clone(&daemon), Arc::clone(&release));
        std::thread::spawn(move || {
            let _guard = d.hold_writer_for_test();
            while !release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
        })
    };
    std::thread::sleep(Duration::from_millis(200)); // let the holder take it

    let shutdown: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let reload: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let runner = {
        let (j, d) = (Arc::clone(&jobs), Arc::clone(&daemon));
        std::thread::spawn(move || pvfsd::jobs::run(j, shutdown, reload, Some(d)))
    };

    // 1. The first step, at start: both regions purged by their own
    //    retention and reported; the old-model folder's trash untouched.
    let s = status_until(&mut member, 5, "both regions reported", |s| s.trash.len() == 2);
    let t1 = s.trash.iter().find(|t| t.region == r1).expect("mediabox-local reported");
    let t2 = s.trash.iter().find(|t| t.region == r2).expect("mediabox-local2 reported");
    assert!(!r1_old.exists(), "10 days old, kept 7: purged");
    assert!(r1_new.exists(), "today's bucket is kept");
    assert!(!r2_old.exists(), "5 days old, kept 3: purged");
    assert!(r2_new.exists(), "2 days old, kept 3: kept");
    assert!(plain_old.exists(), "not a catalogue region: not this purge's");
    assert_eq!((t1.bytes, t1.buckets, t1.oldest_day, t1.retention_days), (2_000, 1, Some(d), 7));
    assert_eq!((t2.bytes, t2.buckets, t2.oldest_day, t2.retention_days), (1_000, 1, Some(d - 2), 3));
    assert_eq!(applied_mark(&data_dir).0, 0, "nothing folded: the cache is exactly as far behind as it was left");
    release.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    drop(fold_lock);
    set_applied_mark(&data_dir, seq, &hash);

    // 2. It keeps running: the measurement moves on, and a bucket that turns
    //    up past retention later is purged by a later step and not reported.
    let first = t1.measured_ms;
    status_until(&mut member, 5, "a later step re-measured", |s| {
        s.trash.iter().any(|t| t.region == r1 && t.measured_ms > first)
    });
    let late = bucket(&local, d - 8, 4_000);
    let deadline = Instant::now() + Duration::from_secs(5);
    while late.exists() {
        assert!(Instant::now() < deadline, "a later step never purged the late bucket");
        std::thread::sleep(Duration::from_millis(50));
    }
    let gone_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    let s = status_until(&mut member, 5, "a report measured after the late purge", |s| {
        s.trash.iter().any(|t| t.region == r1 && t.measured_ms > gone_ms)
    });
    let t1 = s.trash.iter().find(|t| t.region == r1).unwrap();
    assert_eq!((t1.bytes, t1.buckets, t1.oldest_day), (2_000, 1, Some(d)), "the late bucket is not in the report");
    assert_eq!(s.trash.len(), 2, "{:?}", s.trash);
    assert!(plain_old.exists());

    // 3. Shutdown is not held up by the step.
    shutdown.store(true, Ordering::SeqCst);
    let joined = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = runner.join();
        let _ = joined.0.send(());
    });
    assert!(joined.1.recv_timeout(Duration::from_secs(3)).is_ok(), "the runner did not stop");
}
