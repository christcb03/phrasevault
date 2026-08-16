//! F5.8 (doc 17 §7.9): ONE FOLDER AT A TIME. Every projection-mutating
//! critical section (the write path's append+fold, the open-time tail
//! fold, the full rebuild) takes an exclusive flock on `fold.lock`, so a
//! write can never land between another engine's replay segments — the
//! interleave that produced the D69 torn cache. These tests hold the lock
//! the way a mid-rebuild engine would and assert the other paths WAIT.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use pvfs_core::{Engine, NodeSpec, TYPE_FOLDER};

fn hold_fold_lock(dir: &std::path::Path) -> nix::fcntl::Flock<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("fold.lock"))
        .unwrap();
    match nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusiveNonblock) {
        Ok(l) => l,
        Err(_) => panic!("test could not take the fold lock"),
    }
}

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

#[test]
fn a_write_waits_for_the_fold_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    engine.close().unwrap();

    // Another folder is "mid-rebuild": it holds the fold lock.
    let lock = hold_fold_lock(dir.path());
    let released = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::channel();

    let path = dir.path().to_path_buf();
    let seen = released.clone();
    let writer = std::thread::spawn(move || {
        // A clean open folds nothing — it must succeed while the lock is
        // held. Only the WRITE below joins the fold queue.
        let mut e = Engine::open(&path).expect("a clean open takes no fold lock");
        e.add_node(&root, folder("queued")).expect("the write lands after the wait");
        let observed_release = seen.load(Ordering::SeqCst);
        let _ = done_tx.send(());
        observed_release
    });

    // While the lock is held, the write must not complete.
    assert!(
        done_rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "a write completed while another folder held the fold lock"
    );
    released.store(true, Ordering::SeqCst);
    drop(lock);
    assert!(
        done_rx.recv_timeout(Duration::from_secs(30)).is_ok(),
        "the write never completed after the fold lock was released"
    );
    assert!(
        writer.join().unwrap(),
        "the write finished before the fold lock was released"
    );
}

#[test]
fn a_healing_open_waits_for_the_fold_lock() {
    // The D69 tear shape (device table lost at tip): the open self-heals
    // via full_rebuild — and that rebuild must WAIT its turn behind the
    // lock holder, never run beside it.
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    engine.add_node(&root, folder("kept")).unwrap();
    engine.close().unwrap();

    let conn = rusqlite::Connection::open(dir.path().join("index.db")).unwrap();
    conn.execute("DELETE FROM device_keys", []).unwrap();
    drop(conn);

    let lock = hold_fold_lock(dir.path());
    let released = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::channel();

    let path = dir.path().to_path_buf();
    let seen = released.clone();
    let opener = std::thread::spawn(move || {
        let e = Engine::open(&path).expect("the torn cache heals once the lock frees");
        drop(e);
        let observed_release = seen.load(Ordering::SeqCst);
        let _ = done_tx.send(());
        observed_release
    });

    assert!(
        done_rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "a healing rebuild ran while another folder held the fold lock"
    );
    released.store(true, Ordering::SeqCst);
    drop(lock);
    assert!(
        done_rx.recv_timeout(Duration::from_secs(30)).is_ok(),
        "the healing open never completed after the fold lock was released"
    );
    assert!(
        opener.join().unwrap(),
        "the healing rebuild ran before the fold lock was released"
    );
}
