//! D71 W5 — an automated delete moves the file aside, it does not remove it.
//!
//! Once `evict` has reclaimed the ingest box's copy the NAS holds the ONLY
//! copy, and PVFS now has automated paths that destroy files: the mover
//! replacing an upgraded file, and the live mirror following a delete. A bug in
//! either loses data with nothing behind it — so they move it to a trash that
//! an operator can restore from, and a purge reclaims it later.

use std::fs;

use pvfs_core::sync::{move_to_trash, purge_trash, trash_root};

#[test]
fn a_replaced_file_is_recoverable_from_the_trash() {
    let root = tempfile::tempdir().unwrap();
    let episode = root.path().join("Media/TV/Show/Season 03/ep.mkv");
    fs::create_dir_all(episode.parent().unwrap()).unwrap();
    fs::write(&episode, b"the 720p version").unwrap();

    let moved = move_to_trash(root.path(), &episode).unwrap();

    assert!(!episode.exists(), "the original is out of the way");
    assert!(moved.exists(), "and still on disk");
    assert_eq!(fs::read(&moved).unwrap(), b"the 720p version");
    assert!(
        moved.starts_with(trash_root(root.path())),
        "it lives under the dot-prefixed trash, which the watcher ignores"
    );
    // The relative path is preserved, so a restore is obvious.
    assert!(moved.to_string_lossy().ends_with("Media/TV/Show/Season 03/ep.mkv"));
}

#[test]
fn a_file_outside_the_root_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let stray = elsewhere.path().join("stray.mkv");
    fs::write(&stray, b"not ours").unwrap();

    assert!(
        move_to_trash(root.path(), &stray).is_err(),
        "the trash is scoped to its root — never move a file in from outside"
    );
    assert!(stray.exists(), "and the file is untouched");
}

#[test]
fn purge_removes_old_buckets_and_keeps_recent_ones() {
    let root = tempfile::tempdir().unwrap();
    let f = root.path().join("ep.mkv");
    fs::write(&f, b"bytes").unwrap();
    move_to_trash(root.path(), &f).unwrap();

    // Nothing is old enough yet: a fortnight's grace means a fortnight.
    let rep = purge_trash(root.path(), 14, 0).unwrap();
    assert_eq!(rep.removed, 0, "today's deletions stay recoverable");
    assert!(trash_root(root.path()).exists());

    // Age the bucket by renaming it to an older day number.
    let base = trash_root(root.path());
    let bucket = fs::read_dir(&base).unwrap().next().unwrap().unwrap().path();
    let day: u64 = bucket.file_name().unwrap().to_str().unwrap().parse().unwrap();
    fs::rename(&bucket, base.join((day - 30).to_string())).unwrap();

    let rep = purge_trash(root.path(), 14, 0).unwrap();
    assert_eq!(rep.removed, 1, "past the grace period it is reclaimed");
    assert!(rep.freed_bytes > 0, "and it says what it freed");
}

/// Space pressure overrides the grace period — `Data` is 88% full, so an
/// age-only rule would eventually bite.
#[test]
fn space_pressure_purges_even_recent_buckets() {
    let root = tempfile::tempdir().unwrap();
    let f = root.path().join("ep.mkv");
    fs::write(&f, b"bytes").unwrap();
    move_to_trash(root.path(), &f).unwrap();

    // An unreachable free-space floor forces the oldest-first purge.
    let rep = purge_trash(root.path(), 14, u64::MAX).unwrap();
    assert_eq!(rep.removed, 1, "under pressure, recency does not protect it");
}
