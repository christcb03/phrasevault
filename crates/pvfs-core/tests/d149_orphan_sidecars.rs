//! D149 — a manifest sidecar whose file is gone goes to the trash.
//!
//! PVFS took a sidecar along only when it moved the file itself (D145's drain,
//! a retraction). On the production NAS two were left behind by others: Sonarr
//! renamed an episode to add its title, and rclone renamed its upload temp
//! (`<name>.<hash>.partial`) to the real file after the watch had hashed it.
//! The scan's walk now notes them and `scan_binding` moves each one older than
//! `ORPHAN_SIDECAR_GRACE_MS` to the root's `.pvfs-trash` — recoverable, and
//! purged by the region's retention (D148).
//!
//! `HashPolicy::Never` throughout: nothing here is about hashing, and it means
//! the scan never reads a sidecar, so their bytes can be anything.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};
use std::path::{Path, PathBuf};

/// Comfortably past the grace.
const OLD_MS: u64 = pvfs_core::ORPHAN_SIDECAR_GRACE_MS + 10 * 60 * 1_000;

/// Write `bytes` at `p` with an mtime `age_ms` in the past (0 = now).
fn put(p: &Path, bytes: &[u8], age_ms: u64) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
    if age_ms > 0 {
        let t = std::time::SystemTime::now() - std::time::Duration::from_millis(age_ms);
        std::fs::File::options()
            .write(true)
            .open(p)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }
}

/// Whether some day bucket of `root`'s trash holds `rel`.
fn in_trash(root: &Path, rel: &str) -> bool {
    let Ok(days) = std::fs::read_dir(root.join(".pvfs-trash")) else {
        return false;
    };
    days.flatten().any(|d| d.path().join(rel).is_file())
}

fn folder(e: &mut Engine, label: &str) -> String {
    let root = e.identity.root_node_id.clone();
    e.add_node(
        &root,
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

fn bind(e: &mut Engine, folder: &str, lib: &Path) {
    e.bind_folder(
        &folder.to_string(),
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::Never,
        },
    )
    .unwrap();
}

fn orphans_moved(e: &mut Engine, folder: &str) -> u64 {
    e.scan(Some(&folder.to_string()))
        .unwrap()
        .iter()
        .map(|r| r.stats.orphan_sidecars)
        .sum()
}

const SEASON: &str = "TV/Show/Season 01";

/// One of every case. Everything is old enough to move except `.young…`.
fn library(dir: &Path) -> PathBuf {
    let lib = dir.join("lib");
    let season = lib.join(SEASON);
    // A file and its sidecar.
    put(&lib.join("a.mkv"), b"aaa", OLD_MS);
    put(&lib.join(".a.mkv.manifest"), b"sidecar", OLD_MS);
    // The renamed episode: the new name and its sidecar, and the old name's.
    put(&season.join("Show - s01e01 - Pilot.mkv"), b"e1", OLD_MS);
    put(&season.join(".Show - s01e01 - Pilot.mkv.manifest"), b"sidecar", OLD_MS);
    put(&season.join(".Show - s01e01.mkv.manifest"), b"sidecar", OLD_MS);
    // rclone's upload temp, renamed to the real file after the watch hashed it.
    put(&season.join("Show - s01e02.mkv"), b"e2", OLD_MS);
    put(&season.join(".Show - s01e02.mkv.b0a3e24b.partial.manifest"), b"sidecar", OLD_MS);
    // An orphan younger than the grace.
    put(&lib.join(".young.mkv.manifest"), b"sidecar", 0);
    // v1 names (D91): an orphan, and one whose file is there.
    put(&lib.join("gone.mkv.manifest"), b"sidecar", OLD_MS);
    put(&lib.join("kept.mkv"), b"k", OLD_MS);
    put(&lib.join("kept.mkv.manifest"), b"sidecar", OLD_MS);
    // A dotfile that is no sidecar, and a bare `.manifest` that is nobody's.
    put(&lib.join(".hidden"), b"h", OLD_MS);
    put(&lib.join(".manifest"), b"?", OLD_MS);
    lib
}

#[test]
fn an_orphaned_manifest_goes_to_the_trash_and_nothing_else_moves() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let media = folder(&mut e, "Media");
    bind(&mut e, &media, &lib);

    assert_eq!(
        orphans_moved(&mut e, &media),
        3,
        "the renamed episode's, rclone's temp's and the v1 orphan"
    );
    for rel in [
        format!("{SEASON}/.Show - s01e01.mkv.manifest"),
        format!("{SEASON}/.Show - s01e02.mkv.b0a3e24b.partial.manifest"),
        "gone.mkv.manifest".to_string(),
    ] {
        assert!(!lib.join(&rel).exists(), "{rel} should have left the library");
        assert!(in_trash(&lib, &rel), "{rel} should be in the trash, where it can be recovered");
    }
    for rel in [
        "a.mkv".to_string(),
        ".a.mkv.manifest".to_string(),
        format!("{SEASON}/Show - s01e01 - Pilot.mkv"),
        format!("{SEASON}/.Show - s01e01 - Pilot.mkv.manifest"),
        ".young.mkv.manifest".to_string(),
        "kept.mkv".to_string(),
        "kept.mkv.manifest".to_string(),
        ".hidden".to_string(),
        ".manifest".to_string(),
    ] {
        assert!(lib.join(&rel).is_file(), "{rel} must stay where it is");
    }

    // The trash is a dot-directory the walk never enters, so the next pass
    // has nothing left to move.
    assert_eq!(orphans_moved(&mut e, &media), 0);
}

#[test]
fn a_young_orphan_goes_once_it_is_old() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    put(&lib.join("a.mkv"), b"aaa", OLD_MS);
    let side = lib.join(".renamed.mkv.manifest");
    put(&side, b"sidecar", 0);
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let media = folder(&mut e, "Media");
    bind(&mut e, &media, &lib);

    assert_eq!(orphans_moved(&mut e, &media), 0, "inside the grace it waits");
    assert!(side.is_file());

    put(&side, b"sidecar", OLD_MS);
    assert_eq!(orphans_moved(&mut e, &media), 1, "past the grace it goes");
    assert!(in_trash(&lib, ".renamed.mkv.manifest"));
}

#[test]
fn a_catalogue_region_sweeps_too() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    let film = "Movies/Film (2020)";
    put(&lib.join(film).join("Film (2020).mkv"), b"film", OLD_MS);
    // The .mp4 an upgrade replaced with the .mkv — its sidecar stayed.
    put(&lib.join(film).join(".Film (2020).mp4.manifest"), b"sidecar", OLD_MS);
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let region = folder(&mut e, "Library");
    e.region_mark_as(&region, "catalogue", None).unwrap();
    bind(&mut e, &region, &lib);

    assert_eq!(orphans_moved(&mut e, &region), 1);
    assert!(in_trash(&lib, &format!("{film}/.Film (2020).mp4.manifest")));
    assert!(lib.join(film).join("Film (2020).mkv").is_file());
}
