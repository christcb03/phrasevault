//! F0 export tests — doc 17 §3.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use pvfs_core::{
    BindSpec, Engine, ExportMode, ExportSpec, FilePayload, HashPolicy, NodeSpec, TYPE_FILE,
    TYPE_FOLDER,
};

fn new_forest() -> (tempfile::TempDir, Engine, pvfs_core::Mnemonic) {
    let dir = tempfile::tempdir().unwrap();
    let (engine, m) = Engine::init(dir.path()).unwrap();
    (dir, engine, m)
}

fn write_file(path: &Path, contents: &[u8]) {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).unwrap();
    }
    fs::File::create(path).unwrap().write_all(contents).unwrap();
}

fn bind_spec(dir: &Path, policy: HashPolicy) -> BindSpec {
    BindSpec {
        source_uri: pvfs_core::storage::path_to_uri(&fs::canonicalize(dir).unwrap()).unwrap(),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: policy,
    }
}

/// The p1 media fixture: movies/alpha.mkv, movies/beta.mp4, notes.txt bound
/// under a "library" folder, scanned.
fn scanned_library(policy: HashPolicy) -> (tempfile::TempDir, tempfile::TempDir, Engine, String) {
    let (data, mut engine, _m) = new_forest();
    let fixture = tempfile::tempdir().unwrap();
    write_file(&fixture.path().join("movies/alpha.mkv"), b"alpha-bytes");
    write_file(&fixture.path().join("movies/beta.mp4"), b"beta-bytes!");
    write_file(&fixture.path().join("notes.txt"), b"hello notes");
    let root = engine.identity.root_node_id.clone();
    let folder = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "library".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine
        .bind_folder(&folder, bind_spec(fixture.path(), policy))
        .unwrap();
    engine.scan(Some(&folder)).unwrap();
    (data, fixture, engine, folder)
}

fn find_by_label(engine: &Engine, parent: &str, label: &str) -> Option<pvfs_core::ChildEntry> {
    engine
        .children(&parent.to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.node.label == label)
}

// doc 17 §3 — symlink export materializes the tree; entries read through
#[test]
fn symlink_export_materializes_tree() {
    let (_data, _fixture, mut engine, folder) = scanned_library(HashPolicy::Lazy);
    let dest_root = tempfile::tempdir().unwrap();
    let dest = dest_root.path().join("plex");
    let spec = ExportSpec {
        mode: ExportMode::Symlink,
        prune: false,
    };

    let report = engine.export_tree(&folder, &dest, &spec).unwrap();
    assert_eq!(report.exported, 3);
    assert_eq!(report.dirs_created, 1); // movies/
    assert_eq!(report.unchanged, 0);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);

    let alpha = dest.join("movies/alpha.mkv");
    assert!(fs::symlink_metadata(&alpha).unwrap().file_type().is_symlink());
    assert_eq!(fs::read(&alpha).unwrap(), b"alpha-bytes");
    assert_eq!(fs::read(dest.join("notes.txt")).unwrap(), b"hello notes");
    assert!(dest.join(pvfs_core::export::MANIFEST_NAME).exists());

    // re-run: everything already current
    let again = engine.export_tree(&folder, &dest, &spec).unwrap();
    assert_eq!(again.exported, 0);
    assert_eq!(again.unchanged, 3);
    assert_eq!(again.dirs_created, 0);
}

// removals leave stale entries; --prune clears them
#[test]
fn reexport_reports_then_prunes_stale_entries() {
    let (_data, _fixture, mut engine, folder) = scanned_library(HashPolicy::Lazy);
    let dest_root = tempfile::tempdir().unwrap();
    let dest = dest_root.path().join("view");
    let spec = ExportSpec {
        mode: ExportMode::Symlink,
        prune: false,
    };
    engine.export_tree(&folder, &dest, &spec).unwrap();

    // drop alpha out of the tree
    let movies = find_by_label(&engine, &folder, "movies").unwrap();
    let alpha = find_by_label(&engine, &movies.node.id, "alpha.mkv").unwrap();
    engine.remove_link(&alpha.link_id).unwrap();

    let stale_run = engine.export_tree(&folder, &dest, &spec).unwrap();
    assert_eq!(stale_run.stale, vec!["movies/alpha.mkv".to_string()]);
    assert!(dest.join("movies/alpha.mkv").symlink_metadata().is_ok());

    let prune_run = engine
        .export_tree(
            &folder,
            &dest,
            &ExportSpec {
                mode: ExportMode::Symlink,
                prune: true,
            },
        )
        .unwrap();
    assert_eq!(prune_run.pruned, 1);
    assert!(dest.join("movies/alpha.mkv").symlink_metadata().is_err());
    assert!(dest.join("movies/beta.mp4").symlink_metadata().is_ok());
}

// copy mode: real files, verified while copying; a corrupt source is a
// reported skip (and quarantined), never a bad byte in the export
#[test]
fn copy_export_verifies_bytes() {
    let (_data, fixture, mut engine, folder) = scanned_library(HashPolicy::OnAdd);
    let dest_root = tempfile::tempdir().unwrap();
    let dest = dest_root.path().join("copyview");
    let spec = ExportSpec {
        mode: ExportMode::Copy,
        prune: false,
    };

    let report = engine.export_tree(&folder, &dest, &spec).unwrap();
    assert_eq!(report.exported, 3);
    let alpha = dest.join("movies/alpha.mkv");
    assert!(fs::symlink_metadata(&alpha).unwrap().file_type().is_file());
    assert_eq!(fs::read(&alpha).unwrap(), b"alpha-bytes");

    // unchanged on re-run (hash check against the existing copy)
    let again = engine.export_tree(&folder, &dest, &spec).unwrap();
    assert_eq!(again.unchanged, 3);

    // corrupt the source and force a re-copy: the verified read must refuse
    write_file(&fixture.path().join("movies/alpha.mkv"), b"EVIL-bytes!");
    fs::remove_file(&alpha).unwrap();
    let after = engine.export_tree(&folder, &dest, &spec).unwrap();
    assert_eq!(after.skipped.len(), 1, "{:?}", after.skipped);
    assert_eq!(after.skipped[0].path, "movies/alpha.mkv");
    assert!(alpha.symlink_metadata().is_err(), "no unverified copy lands");
}

// same-label siblings both export, disambiguated deterministically
#[test]
fn label_collisions_disambiguate() {
    let (_data, mut engine, _m) = new_forest();
    let fixture = tempfile::tempdir().unwrap();
    write_file(&fixture.path().join("one.bin"), b"first");
    write_file(&fixture.path().join("two.bin"), b"second");
    let root = engine.identity.root_node_id.clone();

    let mut add = |src: &str| {
        let payload = FilePayload {
            content_hash: String::new(),
            size_bytes: 0,
            mime_type: "application/octet-stream".into(),
            original_name: "same.txt".into(),
        };
        let id = engine
            .add_node(
                &root,
                NodeSpec {
                    node_type: TYPE_FILE.into(),
                    label: "same.txt".into(),
                    payload: payload.encode(),
                    is_temp: false,
                    creation_nonce: None,
                },
            )
            .unwrap();
        let uri = pvfs_core::storage::path_to_uri(&fixture.path().join(src)).unwrap();
        engine.add_location(&id, &uri).unwrap();
        id
    };
    let first = add("one.bin");
    let second = add("two.bin");

    let dest_root = tempfile::tempdir().unwrap();
    let dest = dest_root.path().join("flat");
    let report = engine
        .export_tree(
            &root,
            &dest,
            &ExportSpec {
                mode: ExportMode::Symlink,
                prune: false,
            },
        )
        .unwrap();
    assert_eq!(report.exported, 2);
    assert_eq!(fs::read(dest.join("same.txt")).unwrap(), b"first");
    let disambiguated = dest.join(format!("same.txt~{}", &second[..8]));
    assert_eq!(fs::read(&disambiguated).unwrap(), b"second");
    let _ = first;
}

// never adopt a directory the export didn't create
#[test]
fn refuses_foreign_nonempty_dest() {
    let (_data, _fixture, mut engine, folder) = scanned_library(HashPolicy::Lazy);
    let dest_root = tempfile::tempdir().unwrap();
    let dest = dest_root.path().join("occupied");
    write_file(&dest.join("precious.txt"), b"user data");

    let err = engine
        .export_tree(
            &folder,
            &dest,
            &ExportSpec {
                mode: ExportMode::Symlink,
                prune: false,
            },
        )
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("manifest"), "unexpected error: {msg}");
    assert_eq!(fs::read(dest.join("precious.txt")).unwrap(), b"user data");
}
