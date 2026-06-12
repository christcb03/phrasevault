//! P1.5 test plan — doc 05: mounts, registry, resolver, tree paths.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use pvfs_core::fs::HashPolicy;
use pvfs_core::mount::{
    self, enclosing_mount, is_mount, node_at_path, peek_identity, resolve_target, state_dir,
};
use pvfs_core::{PvfsError, Registry};

fn write_file(path: &Path, contents: &[u8]) {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).unwrap();
    }
    fs::File::create(path).unwrap().write_all(contents).unwrap();
}

/// A mount with a small workspace tree, initialized + imported.
fn make_mount() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let mount = fs::canonicalize(dir.path()).unwrap();
    write_file(&mount.join("docs/notes.txt"), b"some notes");
    write_file(&mount.join("photos/2024/pic.jpg"), b"jpegish");
    let (engine, _m, report) = mount::init_forest(&mount, true, HashPolicy::Lazy).unwrap();
    assert_eq!(report.unwrap().stats.added, 2, "imported the mount tree");
    engine.close().unwrap();
    (dir, mount)
}

// doc 05 §1/§5.1 — layout + import; .pvfs is never indexed
#[test]
fn init_creates_state_under_dot_pvfs_and_imports() {
    let (_dir, mount) = make_mount();
    assert!(is_mount(&mount));
    assert!(state_dir(&mount).join("log.db").is_file());
    assert!(state_dir(&mount).join("index.db").is_file());
    assert!(state_dir(&mount).join("device.key").is_file());

    let engine = mount::open_mount(&mount).unwrap();
    let docs = node_at_path(&engine, &["docs".into()]).unwrap();
    let notes = node_at_path(&engine, &["docs".into(), "notes.txt".into()]).unwrap();
    assert_ne!(docs, notes);
    // .pvfs must not have been imported as a folder
    assert!(matches!(
        node_at_path(&engine, &[".pvfs".into()]),
        Err(PvfsError::NotFound { .. })
    ));
    engine.close().unwrap();

    // identity peek without engine open
    let id = peek_identity(&mount).unwrap();
    assert_eq!(id.root_node_id.len(), 64);
}

// doc 05 §3/§5.2 — registry register/list/find/unregister
#[test]
fn registry_lifecycle() {
    let (_dir, mount_path) = make_mount();
    let regdir = tempfile::tempdir().unwrap();
    let reg = Registry::new(regdir.path().to_path_buf());

    assert!(reg.list().unwrap().is_empty());
    reg.register(&mount_path, Some("home")).unwrap();
    let listed = reg.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].alias.as_deref(), Some("home"));
    assert_eq!(listed[0].mount, mount_path);

    // idempotent re-register (alias change) keeps one entry
    reg.register(&mount_path, Some("homey")).unwrap();
    let listed = reg.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].alias.as_deref(), Some("homey"));

    // duplicate alias on a different mount refused
    let (_dir2, mount2) = make_mount();
    assert!(matches!(
        reg.register(&mount2, Some("homey")),
        Err(PvfsError::BadInput { .. })
    ));

    // find by alias and by mount path
    assert!(reg.find("homey").unwrap().is_some());
    assert!(reg
        .find(&mount_path.to_string_lossy())
        .unwrap()
        .is_some());

    // unregister removes entry, never touches .pvfs/
    reg.unregister("homey").unwrap();
    assert!(reg.list().unwrap().is_empty());
    assert!(is_mount(&mount_path), ".pvfs untouched");
    assert!(matches!(
        reg.unregister("homey"),
        Err(PvfsError::NotFound { .. })
    ));

    // alias validation
    assert!(Registry::validate_alias("ok-1").is_ok());
    assert!(Registry::validate_alias("Bad").is_err());
}

// doc 05 §4 — URI + path target resolution
#[test]
fn target_resolution() {
    let (_dir, mount_path) = make_mount();
    let regdir = tempfile::tempdir().unwrap();
    let reg = Registry::new(regdir.path().to_path_buf());
    reg.register(&mount_path, Some("home")).unwrap();

    // alias URI
    let t = resolve_target(&reg, "pvfs://home@local/docs/notes.txt").unwrap();
    assert_eq!(t.mount, mount_path);
    assert_eq!(t.segments, vec!["docs".to_string(), "notes.txt".to_string()]);

    // omitted @server == @local
    let t2 = resolve_target(&reg, "pvfs://home/docs").unwrap();
    assert_eq!(t2.segments, vec!["docs".to_string()]);

    // forest root
    let t3 = resolve_target(&reg, "pvfs://home@local/").unwrap();
    assert!(t3.segments.is_empty());

    // path form URI + absolute path shorthand (longest mount prefix wins)
    let abs = format!("{}/photos/2024", mount_path.display());
    for arg in [format!("pvfs://{abs}"), abs.clone()] {
        let t = resolve_target(&reg, &arg).unwrap();
        assert_eq!(t.mount, mount_path);
        assert_eq!(t.segments, vec!["photos".to_string(), "2024".to_string()]);
    }

    // remote server is P4
    assert!(matches!(
        resolve_target(&reg, "pvfs://home@elsewhere/docs"),
        Err(PvfsError::BadInput { .. })
    ));
    // unknown alias
    assert!(matches!(
        resolve_target(&reg, "pvfs://nope/docs"),
        Err(PvfsError::NotFound { .. })
    ));
    // relative path
    assert!(matches!(
        resolve_target(&reg, "docs/notes"),
        Err(PvfsError::BadInput { .. })
    ));
    // absolute path outside any mount
    assert!(matches!(
        resolve_target(&reg, "/definitely/not/a/mount"),
        Err(PvfsError::NotFound { .. })
    ));

    // tree-path → node, and a miss
    let engine = mount::open_mount(&mount_path).unwrap();
    let hit = node_at_path(&engine, &t.segments.clone()).unwrap();
    assert_eq!(hit.len(), 64);
    assert!(matches!(
        node_at_path(&engine, &["docs".into(), "missing".into()]),
        Err(PvfsError::NotFound { .. })
    ));
    engine.close().unwrap();
}

// doc 05 §2/§5.3 — portable forests: copy the whole mount, open by path
#[test]
fn portable_forest_copy() {
    let (_dir, mount_path) = make_mount();
    let usb = tempfile::tempdir().unwrap();
    let copy = usb.path().join("project");
    copy_dir(&mount_path, &copy);
    let copy = fs::canonicalize(&copy).unwrap();

    assert!(is_mount(&copy));
    // no registry entry needed
    let reg = Registry::new(tempfile::tempdir().unwrap().path().to_path_buf());
    let t = resolve_target(&reg, &format!("{}/docs/notes.txt", copy.display())).unwrap();
    assert_eq!(t.mount, copy);

    let engine = mount::open_mount(&copy).unwrap();
    let node = node_at_path(&engine, &t.segments).unwrap();
    assert!(engine.get_node(&node).unwrap().is_some());
    engine.close().unwrap();

    // enclosing_mount finds the nearest mount from a subpath
    assert_eq!(
        enclosing_mount(&copy.join("photos/2024")).unwrap(),
        copy
    );
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), &dest).unwrap();
        }
    }
}
