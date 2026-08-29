//! Nothing waits forever.
//!
//! `lock_folds` took one non-blocking flock, printed "waiting for another pvfs
//! process folding this forest…", and then blocked on `LockExclusive` — with no
//! deadline at all. In a CLI that is merely rude. In the library MOUNT it is
//! fatal: fuser's session is single-threaded, so a handler parked on that lock
//! stops answering `getattr` and `readdir` too, and the filesystem is dead while
//! its process looks perfectly healthy — alive, sleeping, 14 MB.
//!
//! That is precisely how `/mnt/pvfs-root` came up after a reboot, beside a
//! daemon busy folding a backlog: unit `active`, `mountpoint -q` timing out,
//! readers stuck in uninterruptible sleep that `timeout` could not kill, and a
//! hung branch inside the union the arrs read.
//!
//! Bounded, the same contention returns `Busy`, which callers already treat as
//! transient. A slow fold costs a retry instead of a mount.

use std::time::{Duration, Instant};

/// Hold the fold lock the way another process would, from a thread.
fn hold_fold_lock(dir: &std::path::Path) -> std::sync::mpsc::Sender<()> {
    let path = dir.join("fold.lock");
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let _l = nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusive).unwrap();
        ready_tx.send(()).unwrap();
        // Hold it until told to let go — or until the test ends.
        let _ = rx.recv_timeout(Duration::from_secs(120));
    });
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    tx
}

/// The property that matters: contention ENDS, and says why.
#[test]
fn a_contended_fold_gives_up_instead_of_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let _holder = hold_fold_lock(dir.path());

    let started = Instant::now();
    let err = pvfs_core::projection::try_fold_lock_for_test(
        dir.path(),
        Duration::from_millis(600),
    )
    .expect_err("the lock is held, so this must not succeed");
    let waited = started.elapsed();

    assert!(
        waited < Duration::from_secs(10),
        "it gave up after {waited:?} — the point is that it gives up at all"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("busy") || msg.contains("Busy") || msg.contains("folding"),
        "and says the forest is being folded, so the caller can retry: {msg}"
    );
}

/// Uncontended, it must still be immediate — the bound is a ceiling, not a wait.
#[test]
fn an_uncontended_fold_is_immediate() {
    let dir = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let got = pvfs_core::projection::try_fold_lock_for_test(
        dir.path(),
        Duration::from_secs(30),
    );
    assert!(got.is_ok(), "nothing holds it, so it is taken at once");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "and without paying the budget to find that out"
    );
}

/// Once the holder lets go, the next taker gets it — the lock still works.
#[test]
fn the_lock_is_handed_over_when_released() {
    let dir = tempfile::tempdir().unwrap();
    let holder = hold_fold_lock(dir.path());
    assert!(
        pvfs_core::projection::try_fold_lock_for_test(
            dir.path(),
            Duration::from_millis(300)
        )
        .is_err(),
        "held, so refused"
    );
    drop(holder); // releases the flock when that thread returns
    let mut got = false;
    for _ in 0..40 {
        if pvfs_core::projection::try_fold_lock_for_test(
            dir.path(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            got = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(got, "released, so the next taker gets it");
}
