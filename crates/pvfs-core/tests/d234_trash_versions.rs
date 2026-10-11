//! PVOS D234 — the trash keeps every version.
//!
//! A deletion went to `.pvfs-trash/<day>/<path>` by `rename(2)`, so a second
//! deletion of the same path on the same day replaced the first in the trash:
//! on mediabox (2026-10-11) a file renamed over and then removed left only
//! the second. Now the day's next bucket (`<day>.1`, `<day>.2`, …) takes a
//! path that is already in the day's buckets, nothing in the trash is ever
//! replaced, and a file's sidecars go into its own bucket.

use std::path::{Path, PathBuf};

use pvfs_core::sync::{self, TrashPick};

const REL: &str = "TV/Show/Season 01/Show - s01e01.en.srt";

fn write(root: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, bytes).unwrap();
    p
}

/// A file with a v3 sidecar naming its real hash, as the watch leaves it.
fn file_with_sidecar(root: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
    let p = write(root, rel, bytes);
    let hash = blake3::hash(bytes).to_hex().to_string();
    sync::write_manifest_sidecar(&p, Some(&hash), &[]).unwrap();
    assert!(sync::manifest_sidecar_path(&p).is_file());
    p
}

/// The bucket a trashed path landed in (its name under `.pvfs-trash`).
fn bucket_of(root: &Path, dest: &Path) -> String {
    let rest = dest.strip_prefix(sync::trash_root(root)).unwrap();
    rest.components().next().unwrap().as_os_str().to_string_lossy().into_owned()
}

#[test]
fn bucket_names_parse_strictly() {
    assert_eq!(sync::trash_bucket("20737"), Some((20737, 0)));
    assert_eq!(sync::trash_bucket("20737.1"), Some((20737, 1)));
    assert_eq!(sync::trash_bucket("20737.12"), Some((20737, 12)));
    for bad in ["20737.0", "20737.", ".1", "20737.1.2", "20737.x", "x", "", "-1", "20737 "] {
        assert_eq!(sync::trash_bucket(bad), None, "{bad:?}");
    }
    assert_eq!(sync::trash_bucket_name(20737, 0), "20737");
    assert_eq!(sync::trash_bucket_name(20737, 3), "20737.3");
    assert_eq!(TrashPick::parse("20737"), Some(TrashPick::Day(20737)));
    assert_eq!(TrashPick::parse("20737.2"), Some(TrashPick::Bucket(20737, 2)));
    assert_eq!(TrashPick::parse("today"), None);

    // D232's unstick names a bucket by path; a versioned one is a bucket too.
    let t = Path::new("/srv/lib/.pvfs-trash");
    assert_eq!(sync::trash_bucket_path(&t.join("20737.2")), Some((t.to_path_buf(), 20737)));
    assert_eq!(sync::trash_bucket_path(&t.join("20737")), Some((t.to_path_buf(), 20737)));
    for bad in ["20737.x", "20737.", ".1", "20737.1.2"] {
        assert_eq!(sync::trash_bucket_path(&t.join(bad)), None, "{bad:?}");
    }
}

#[test]
fn three_deletions_of_one_path_in_a_day_are_three_versions_each_with_its_sidecar() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let mut buckets = Vec::new();
    for words in ["first words", "second words", "third words"] {
        let f = file_with_sidecar(root, REL, words.as_bytes());
        let dest = sync::move_to_trash_with_sidecar(root, &f).unwrap();
        assert!(!f.exists(), "moved, not copied");
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), words, "nothing replaced");
        // the sidecar beside ITS file, in ITS bucket, still describing it
        let size = std::fs::metadata(&dest).unwrap().len();
        assert_eq!(
            sync::sidecar_whole_hash(&dest, size),
            Some(blake3::hash(words.as_bytes()).to_hex().to_string()),
            "the sidecar went with its own version"
        );
        buckets.push(bucket_of(root, &dest));
    }
    let day = &buckets[0];
    assert_eq!(buckets, vec![day.clone(), format!("{day}.1"), format!("{day}.2")]);

    // ls: every version, newest first; sidecars unlisted
    let all = sync::list_trash(root);
    let shown: Vec<(&str, u32, &str)> = all.iter().map(|e| (e.bucket.as_str(), e.version, e.rel_path.as_str())).collect();
    assert_eq!(shown, vec![(buckets[2].as_str(), 2, REL), (buckets[1].as_str(), 1, REL), (buckets[0].as_str(), 0, REL)]);
    assert_eq!(sync::trash_stats(root).buckets, 3);
}

#[test]
fn a_restore_takes_the_newest_or_the_version_asked_for_and_never_overwrites() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let mut day = 0;
    for words in ["first words", "second words", "third words"] {
        let f = file_with_sidecar(root, REL, words.as_bytes());
        let dest = sync::move_to_trash_with_sidecar(root, &f).unwrap();
        day = sync::trash_bucket(&bucket_of(root, &dest)).unwrap().0;
    }
    // default: the newest
    let done = sync::restore_from_trash(root, REL, None).unwrap();
    assert_eq!(done.restored, vec![REL.to_string()]);
    assert_eq!(std::fs::read_to_string(root.join(REL)).unwrap(), "third words");
    assert!(sync::manifest_sidecar_path(&root.join(REL)).is_file(), "with its sidecar");
    // a path in the way is reported, not overwritten
    let done = sync::restore_from_trash_pick(root, REL, Some(TrashPick::Bucket(day, 1))).unwrap();
    assert_eq!(done.in_the_way, vec![REL.to_string()]);
    assert_eq!(std::fs::read_to_string(root.join(REL)).unwrap(), "third words");
    // exactly the bucket asked for
    std::fs::remove_file(root.join(REL)).unwrap();
    std::fs::remove_file(sync::manifest_sidecar_path(&root.join(REL))).unwrap();
    let done = sync::restore_from_trash_pick(root, REL, Some(TrashPick::Bucket(day, 1))).unwrap();
    assert_eq!(done.restored, vec![REL.to_string()]);
    assert_eq!(std::fs::read_to_string(root.join(REL)).unwrap(), "second words");
    // "a day" is that day's newest still in the trash: the first version
    std::fs::remove_file(root.join(REL)).unwrap();
    let done = sync::restore_from_trash_pick(root, REL, Some(TrashPick::Day(day))).unwrap();
    assert_eq!(done.restored, vec![REL.to_string()]);
    assert_eq!(std::fs::read_to_string(root.join(REL)).unwrap(), "first words");
    assert!(sync::list_trash(root).is_empty(), "every version came back once: {:?}", sync::list_trash(root));
    // and an empty version bucket is tidied away
    assert!(!sync::trash_root(root).join(format!("{day}.1")).exists());
}

#[test]
fn a_trash_already_holding_the_path_or_its_sidecar_sends_the_next_one_on() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // a first deletion with no sidecar
    let f = write(root, REL, b"no sidecar");
    let first = sync::move_to_trash(root, &f).unwrap();
    let day = bucket_of(root, &first);
    // a stray sidecar alone in the day's `.1` bucket (nothing else there)
    let stray = sync::trash_root(root).join(format!("{day}.1")).join(REL);
    std::fs::create_dir_all(stray.parent().unwrap()).unwrap();
    std::fs::write(sync::manifest_sidecar_path(&stray), b"someone else's sidecar").unwrap();
    // the next deletion, with a sidecar: `<day>` has the file, `<day>.1` the
    // sidecar's path — `<day>.2` takes both, and nothing is replaced
    let f = file_with_sidecar(root, REL, b"with a sidecar");
    let dest = sync::move_to_trash_with_sidecar(root, &f).unwrap();
    assert_eq!(bucket_of(root, &dest), format!("{day}.2"));
    assert_eq!(std::fs::read(&first).unwrap(), b"no sidecar");
    assert_eq!(std::fs::read(sync::manifest_sidecar_path(&stray)).unwrap(), b"someone else's sidecar");
    assert!(sync::manifest_sidecar_path(&dest).is_file());
}

#[test]
fn a_folder_trashed_twice_in_a_day_is_two_versions() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let mut buckets = Vec::new();
    for words in ["one", "two"] {
        write(root, "TV/Old Show/Season 01/e01.nfo", words.as_bytes());
        let dest = sync::move_to_trash(root, &root.join("TV/Old Show")).unwrap();
        assert!(dest.is_dir());
        buckets.push(bucket_of(root, &dest));
    }
    assert_eq!(buckets[1], format!("{}.1", buckets[0]));
    let t = sync::trash_root(root);
    assert_eq!(std::fs::read(t.join(&buckets[0]).join("TV/Old Show/Season 01/e01.nfo")).unwrap(), b"one");
    assert_eq!(std::fs::read(t.join(&buckets[1]).join("TV/Old Show/Season 01/e01.nfo")).unwrap(), b"two");
}

#[test]
fn retention_takes_every_bucket_of_a_day_and_the_space_rule_takes_them_all() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let t = sync::trash_root(root);
    for (bucket, rel) in [("100", "a.mkv"), ("100.1", "a.mkv"), ("100.2", "b.mkv"), ("101", "c.mkv")] {
        std::fs::create_dir_all(t.join(bucket)).unwrap();
        std::fs::write(t.join(bucket).join(rel), b"old").unwrap();
    }
    // and today's, which retention keeps
    let f = write(root, REL, b"today");
    sync::move_to_trash(root, &f).unwrap();
    assert_eq!(sync::trash_stats(root).buckets, 5);
    assert_eq!(sync::trash_stats(root).oldest_day, Some(100));

    let p = sync::purge_trash(root, 7, 0).unwrap();
    assert_eq!(p.removed, 4, "both old days, every version of each");
    assert!(p.stuck.is_empty());
    for gone in ["100", "100.1", "100.2", "101"] {
        assert!(!t.join(gone).exists(), "{gone}");
    }
    assert_eq!(sync::list_trash(root).len(), 1, "today's stays");

    // the space rule (a floor no disk meets) takes the rest, oldest first
    let f = write(root, REL, b"today, again");
    sync::move_to_trash(root, &f).unwrap();
    assert_eq!(sync::trash_stats(root).buckets, 2);
    let p = sync::purge_trash(root, 7, u64::MAX).unwrap();
    assert_eq!(p.removed, 2);
    assert!(sync::list_trash(root).is_empty());
}

#[test]
fn a_reader_finds_a_version_in_a_later_bucket_by_its_hash() {
    // D220 — a holder serves a file it trashed mid-read, by hash, from the
    // trash: a version in `<day>.1` is found as one in `<day>` is.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let f = file_with_sidecar(root, REL, b"version one");
    let one = sync::move_to_trash_with_sidecar(root, &f).unwrap();
    let f = file_with_sidecar(root, REL, b"version two");
    let two = sync::move_to_trash_with_sidecar(root, &f).unwrap();
    let h1 = blake3::hash(b"version one").to_hex().to_string();
    let h2 = blake3::hash(b"version two").to_hex().to_string();
    assert_eq!(sync::trashed_with_hash(root, &h1).map(|(p, _)| p), Some(one));
    assert_eq!(sync::trashed_with_hash(root, &h2), Some((two, 11)));
}

#[test]
fn restore_identical_still_brings_back_only_the_same_file_across_regions() {
    // D170 — one delete through the view trashes the same file in every
    // region that held it; each region numbers its own buckets, so region A
    // (which trashed the path once already today) has it in `<day>.1` and B
    // in `<day>`. Both come back; A's older, different version stays.
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
    let f = file_with_sidecar(&a, REL, b"an older, different file");
    sync::move_to_trash_with_sidecar(&a, &f).unwrap();
    let f = file_with_sidecar(&a, REL, b"the file the view deleted");
    sync::move_to_trash_with_sidecar(&a, &f).unwrap();
    let f = file_with_sidecar(&b, REL, b"the file the view deleted");
    sync::move_to_trash_with_sidecar(&b, &f).unwrap();

    let done = sync::restore_identical(&[a.as_path(), b.as_path()], REL, None).unwrap();
    assert_eq!(done.per_root[0].restored, vec![REL.to_string()]);
    assert_eq!(done.per_root[1].restored, vec![REL.to_string()]);
    assert_eq!(std::fs::read(a.join(REL)).unwrap(), b"the file the view deleted");
    assert_eq!(std::fs::read(b.join(REL)).unwrap(), b"the file the view deleted");
    assert_eq!(sync::list_trash(&a).len(), 1, "the older, different version stays in A's trash");
}
