//! D160 — a log region's deletions ask the disk whether a file is gone.
//!
//! `scan_binding`'s step 3 retired each tracked location the walk did not list
//! whose path failed `Path::exists`, and that is false on ANY stat error. A
//! directory that stops being searchable is skipped by the walk as
//! `unreadable`, so every location beneath it was retired by the next complete
//! pass, and added back by the first pass after the chmod was undone. D156's
//! `gone_from_disk` now decides, as it does for the catalogue sweep: gone is
//! ENOENT or ENOTDIR, and nothing else.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use pvfs_core::fs::ScanStats;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

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

/// A forest at `data` whose `Library` is a log region (not marked catalogue:
/// the scan ingests nodes) bound to `lib`.
fn log_forest(data: &Path, lib: &Path) -> (Engine, String) {
    let (mut e, _mn) = Engine::init(data).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = folder(&mut e, &root, "Library");
    e.bind_folder(
        &region,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    (e, region)
}

/// Two files at the top and two episodes in `Season 01`, each different.
fn library(dir: &Path) -> PathBuf {
    let lib = dir.join("lib");
    let season = lib.join("Season 01");
    std::fs::create_dir_all(&season).unwrap();
    std::fs::write(lib.join("e0.mkv"), b"zero").unwrap();
    std::fs::write(lib.join("e1.mkv"), b"the first").unwrap();
    std::fs::write(season.join("s01e01.mkv"), b"pilot").unwrap();
    std::fs::write(season.join("s01e02.mkv"), b"the second episode").unwrap();
    lib
}

fn pass(e: &mut Engine, region: &str) -> ScanStats {
    e.scan_routed(Some(&region.to_string()), None, 0).unwrap().remove(0).stats
}

fn child(e: &Engine, parent: &str, label: &str) -> String {
    e.children(&parent.to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.label == label)
        .map(|c| c.node.id)
        .unwrap_or_else(|| panic!("no node for {label}"))
}

/// The file nodes under `Season 01`, by name: (name, node, live locations).
fn season(e: &Engine, region: &str) -> Vec<(String, String, Vec<String>)> {
    let s = child(e, region, "Season 01");
    let mut v: Vec<_> = e
        .children(&s)
        .unwrap()
        .into_iter()
        .filter(|c| c.node.node_type == TYPE_FILE)
        .map(|c| {
            let locs = e.locations(&c.node.id).unwrap();
            (c.label, c.node.id, locs)
        })
        .collect();
    v.sort();
    v
}

fn root_user() -> bool {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipped: root reads and searches through mode 000 anyway");
        return true;
    }
    false
}

/// The case D160 fixes: not being able to look is not the files going. The
/// directory is skipped as `unreadable`, every node and location beneath it
/// stays, and the log does not move: no remove now, and no add to undo it
/// once the directory can be searched again.
#[test]
fn a_directory_that_cannot_be_searched_keeps_its_locations_and_nodes() {
    if root_user() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    let (mut e, region) = log_forest(&dir.path().join("forest"), &lib);
    assert_eq!(pass(&mut e, &region).added, 4);
    let before = season(&e, &region);
    assert_eq!(before.len(), 2, "{before:?}");
    assert!(before.iter().all(|(_, _, locs)| locs.len() == 1), "{before:?}");
    let tip = e.log_tip().unwrap();

    let s = lib.join("Season 01");
    std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o000)).unwrap();
    let st = pass(&mut e, &region);
    std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!st.cancelled);
    assert_eq!(
        (st.unreadable, st.removed, st.needs_attention),
        (1, 0, 0),
        "not being able to look is not the files going"
    );
    assert_eq!(season(&e, &region), before, "every node and location beneath it stays");
    assert_eq!(e.log_tip().unwrap(), tip, "not one removal in the log");

    // Searchable again: nothing to re-add, because nothing was taken away.
    let st = pass(&mut e, &region);
    assert_eq!((st.added, st.removed, st.unchanged), (0, 0, 4));
    assert_eq!(season(&e, &region), before);
    assert_eq!(e.log_tip().unwrap(), tip, "and no add undoing one");
}

/// The other side, so step 3 still retires what is really gone: a directory
/// removed (ENOENT beneath it) or replaced by a file of the same name (ENOTDIR
/// beneath it) takes the locations of the files it held.
#[test]
fn a_directory_that_is_really_gone_still_retires_what_was_beneath_it() {
    for replaced_by_a_file in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let lib = library(dir.path());
        let (mut e, region) = log_forest(&dir.path().join("forest"), &lib);
        assert_eq!(pass(&mut e, &region).added, 4);
        let before = season(&e, &region);

        let s = lib.join("Season 01");
        std::fs::remove_dir_all(&s).unwrap();
        if replaced_by_a_file {
            std::fs::write(&s, b"not a directory any more").unwrap();
        }
        let st = pass(&mut e, &region);
        assert_eq!(st.removed, 2, "replaced by a file: {replaced_by_a_file}");
        for (name, id, _) in &before {
            assert!(
                e.locations(id).unwrap().is_empty(),
                "{name}'s location is retired (replaced by a file: {replaced_by_a_file})"
            );
        }
    }
}
