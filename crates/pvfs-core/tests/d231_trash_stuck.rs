//! PVOS D231 — one trash bucket that will not all go does not stop the purge.
//!
//! 2026-10-09 8:01 PM: mediabox's holder logged `trash purge failed: c020473f:
//! I/O error during purge trash bucket: Permission denied` and Grafana paged
//! "Disk errors on mediabox". Two buckets had been made by `sudo pvfs trash
//! put` (root's), and the daemon (chris) could not empty them once they aged
//! past retention. `purge_trash` returned at the first such bucket, so every
//! newer bucket — and the space rule's purge — waited behind it, and the
//! error named neither the bucket nor what in it would not go.
//!
//! A folder made read-only stands in for root's: removing what is in it
//! fails the same way (EACCES) for a process that does not own it — and for
//! one that does but may not write it. Root removes it anyway, so these need
//! a non-root test user (the pipeline's).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use pvfs_core::sync::{purge_region, purge_trash, trash_root};

fn root_user() -> bool {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipped: root removes from a read-only folder anyway");
        return true;
    }
    false
}

fn today() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 86_400
}

fn write(p: &Path, bytes: &[u8]) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, bytes).unwrap();
}

/// A bucket `day` under `root` with one episode in it.
fn bucket(root: &Path, day: u64, bytes: usize) -> PathBuf {
    let b = trash_root(root).join(day.to_string());
    write(&b.join("TV/Show/Season 1/ep.mkv"), &vec![7u8; bytes]);
    b
}

/// Lock `dir` the way a folder of root's is locked to the daemon: what is in
/// it cannot be removed.
fn lock(dir: &Path) {
    fs::set_permissions(dir, fs::Permissions::from_mode(0o555)).unwrap();
}

fn unlock(dir: &Path) {
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn a_stuck_bucket_is_named_and_every_other_bucket_still_goes() {
    if root_user() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let d = today();
    // the incident's shape: the OLDEST bucket is the stuck one
    let stuck = bucket(root.path(), d - 30, 1_000);
    write(&stuck.join("Movies/Film (2020)/film.mkv"), &[1u8; 4_000]);
    write(&stuck.join("TV/Show/Season 1/ep.en.srt"), b"subtitle");
    let locked = stuck.join("TV/Show/Season 1");
    lock(&locked);
    let newer = bucket(root.path(), d - 20, 2_000);
    let recent = bucket(root.path(), d, 3_000);

    let rep = purge_trash(root.path(), 14, 0).expect("a stuck bucket is not an error of the purge");
    unlock(&locked); // tempdir cleanup, and the asserts below do not need it

    assert_eq!(rep.removed, 1, "the newer bucket past retention went: {rep:?}");
    assert!(!newer.exists(), "the newer bucket is not kept behind the stuck one");
    assert!(recent.exists(), "retention still keeps today's bucket");
    assert_eq!(rep.stuck.len(), 1, "{rep:?}");
    let s = &rep.stuck[0];
    assert_eq!(s.day, d - 30);
    assert_eq!(s.bucket, stuck);
    // the first entry, in name order, that would not go
    assert_eq!(s.first, locked.join("ep.en.srt"), "{s:?}");
    assert!(s.error.contains("Permission denied"), "{s:?}");
    assert_eq!(s.folder_uid, Some(nix::unistd::geteuid().as_raw()), "the locked folder's owner");
    // everything it could remove went: the film, its folder
    assert!(!stuck.join("Movies").exists(), "what could be removed was: {s:?}");
    assert_eq!(s.left_bytes, 1_000 + 8, "the two files in the locked folder are left: {s:?}");
    // ep.mkv, ep.en.srt, and the folders up to the bucket (Season 1, Show, TV, the bucket)
    assert_eq!(s.left_entries, 6, "{s:?}");
    assert_eq!(rep.freed_bytes, 2_000 + 4_000, "the newer bucket and the film: {rep:?}");

    let line = s.describe();
    assert!(line.contains(&format!("trash bucket {} not removed", d - 30)), "{line}");
    assert!(line.contains(&locked.join("ep.en.srt").display().to_string()), "{line}");
    assert!(line.contains("Permission denied"), "{line}");
    assert!(!line.contains("I/O error"), "not worded as a disk fault (the Grafana disk rule): {line}");

    // fixed (as `chown -R` fixed mediabox's): the next pass removes it
    let rep = purge_trash(root.path(), 14, 0).unwrap();
    assert_eq!((rep.removed, rep.stuck.len()), (1, 0), "{rep:?}");
    assert!(!stuck.exists());
}

/// The space rule purges oldest-first past retention; a stuck bucket used to
/// end it too.
#[test]
fn space_pressure_goes_past_a_stuck_bucket() {
    if root_user() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let d = today();
    let stuck = bucket(root.path(), d - 1, 1_000);
    let locked = stuck.join("TV/Show/Season 1");
    lock(&locked);
    let newest = bucket(root.path(), d, 2_000);

    let rep = purge_trash(root.path(), 14, u64::MAX).unwrap();
    unlock(&locked);

    assert_eq!(rep.stuck.len(), 1, "{rep:?}");
    assert_eq!(rep.removed, 1, "under pressure the newer bucket still goes: {rep:?}");
    assert!(!newest.exists());
}

/// The second walk (after `remove_dir_all` fails) never follows a link out
/// of the trash: a link is removed as a link.
#[test]
fn the_walk_after_a_failure_never_follows_a_link() {
    if root_user() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let precious = outside.path().join("Movies/keep.mkv");
    write(&precious, b"not the trash's");
    let d = today();
    let b = bucket(root.path(), d - 30, 10);
    // `A…` sorts before `TV`: the links are met before the locked folder
    std::os::unix::fs::symlink(outside.path(), b.join("A-link-to-a-folder")).unwrap();
    std::os::unix::fs::symlink(&precious, b.join("A-link-to-a-file")).unwrap();
    let locked = b.join("TV/Show/Season 1");
    lock(&locked);

    let rep = purge_trash(root.path(), 14, 0).unwrap();
    unlock(&locked);

    assert_eq!(rep.stuck.len(), 1, "{rep:?}");
    assert!(precious.exists(), "nothing outside the trash is touched");
    assert!(outside.path().join("Movies").exists());
    assert!(fs::symlink_metadata(b.join("A-link-to-a-folder")).is_err(), "the link itself went");
    assert!(fs::symlink_metadata(b.join("A-link-to-a-file")).is_err(), "the link itself went");
}

/// A bucket whose own folder cannot be read is named as itself.
#[test]
fn an_unreadable_bucket_is_named_as_itself() {
    if root_user() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let d = today();
    let b = bucket(root.path(), d - 30, 10);
    fs::set_permissions(&b, fs::Permissions::from_mode(0o000)).unwrap();

    let rep = purge_trash(root.path(), 14, 0).unwrap();
    fs::set_permissions(&b, fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(rep.stuck.len(), 1, "{rep:?}");
    assert_eq!(rep.stuck[0].first, b, "{rep:?}");
    assert!(rep.stuck[0].error.contains("Permission denied"), "{rep:?}");
}

/// A region's purge reports its stuck bucket and still says what is kept.
#[test]
fn a_regions_purge_reports_the_stuck_bucket_with_what_is_kept() {
    if root_user() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let d = today();
    let stuck = bucket(root.path(), d - 30, 1_000);
    let locked = stuck.join("TV/Show/Season 1");
    lock(&locked);
    bucket(root.path(), d, 3_000);

    let t = purge_region("c020473f".into(), root.path(), 7).unwrap();
    unlock(&locked);

    assert_eq!(t.purge.stuck.len(), 1, "{t:?}");
    assert_eq!(t.kept.buckets, 2, "the stuck bucket is still kept: {t:?}");
    assert_eq!(t.kept.oldest_day, Some(d - 30), "{t:?}");
}

// ---- the forest's files are used only as their owner (`sudo pvfs`) ---------

/// Root, or any other user, is refused a forest whose files are another's,
/// and told whom to run it as. Default-deny: nothing is opened.
#[test]
fn another_users_forest_is_refused_with_whom_to_run_it_as() {
    use pvfs_core::mount::check_forest_user_for;
    let dir = Path::new("/opt/pvfs/media/.pvfs");
    assert!(check_forest_user_for(dir, 1000, 1000).is_ok(), "the owner itself");
    let e = check_forest_user_for(dir, 1000, 0).unwrap_err();
    assert!(matches!(e, pvfs_core::PvfsError::Forbidden { .. }), "{e:?}");
    let text = e.to_string();
    assert!(text.contains("as root (uid 0)"), "{text}");
    assert!(text.contains("would be root's"), "{text}");
    assert!(text.contains("/opt/pvfs/media/.pvfs"), "{text}");
    assert!(text.contains("sudo -u "), "{text}");
    let e = check_forest_user_for(dir, 1000, 1001).unwrap_err().to_string();
    assert!(e.contains("would be uid 1001's"), "not only root: {e}");
    // root's forest and a user: usually a `sudo` init — fix-permissions
    let e = check_forest_user_for(dir, 0, 1000).unwrap_err().to_string();
    assert!(e.contains("belong to root (uid 0)"), "{e}");
    assert!(e.contains("sudo pvfs forest fix-permissions --mount /opt/pvfs/media"), "{e}");
}

/// A data dir that is not there yet is nobody's: creating a forest decides
/// whose it is (`init_forest`).
#[test]
fn a_forest_not_made_yet_is_not_refused() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(pvfs_core::mount::check_forest_user(&tmp.path().join("nothing/.pvfs")).is_ok());
    assert!(pvfs_core::mount::check_forest_user(tmp.path()).is_ok(), "this user's own");
}

/// Every engine open checks it: a forest made by this user opens, and the
/// rule's refusal is what `Engine::open` returns for another user's (shown
/// with the rule itself; a test user cannot give a folder away — the smoke
/// suite does that with real sudo).
#[test]
fn the_engine_opens_this_users_own_forest() {
    let tmp = tempfile::tempdir().unwrap();
    let (e, _m) = pvfs_core::Engine::init(&tmp.path().join("forest")).unwrap();
    let dir = e.data_dir().to_path_buf();
    e.close().unwrap();
    pvfs_core::Engine::open(&dir).unwrap().close().unwrap();
    pvfs_core::Engine::open_read_view(&dir).map(|_| ()).unwrap();
}
