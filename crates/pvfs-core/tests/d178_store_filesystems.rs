//! PVOS D178 — a box reports every filesystem it stores on, not only its
//! data dir's: mediabox's regions sit on two 98 %-full disks while its data
//! dir's had 339 GB free, and that one number was all the page showed.

use std::path::Path;

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn region(e: &mut Engine, label: &str, root: &Path) -> String {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(root.join("a.mkv"), label.as_bytes()).unwrap();
    let top = e.identity.root_node_id.clone();
    let r = e
        .add_node(
            &top,
            NodeSpec { node_type: TYPE_FOLDER.into(), label: label.into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
        )
        .unwrap();
    e.region_mark_as(&r, "catalogue", None).unwrap();
    e.bind_folder(
        &r,
        BindSpec {
            source_uri: format!("file://{}", root.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&r), None, 0).unwrap();
    r
}

#[test]
fn each_filesystem_once_the_data_dirs_first_with_the_regions_on_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, _) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    assert_eq!(e.store_filesystems().unwrap().len(), 1, "no region: the data dir's alone");

    let a = region(&mut e, "A", &tmp.path().join("a"));
    let b = region(&mut e, "B", &tmp.path().join("b"));
    // A second filesystem, when the host has one to offer: the first
    // writable candidate on another device than the test's own tempdir (the
    // pipeline's TMPDIR can itself be /dev/shm).
    let here = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(tmp.path()).unwrap().dev()
    };
    let other = ["/dev/shm", "/tmp", "/var/tmp"].into_iter().map(Path::new).find(|p| {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).map(|m| m.dev() != here).unwrap_or(false) && tempfile::tempdir_in(p).is_ok()
    });
    let far = other.map(|o| {
        let d = tempfile::tempdir_in(o).unwrap();
        let c = region(&mut e, "C", &d.path().join("c"));
        (d, c, o.to_path_buf())
    });
    // A region marked but bound by nobody here is not a store of this box.
    let top = e.identity.root_node_id.clone();
    let foreign = e
        .add_node(&top, NodeSpec { node_type: TYPE_FOLDER.into(), label: "F".into(), payload: Vec::new(), is_temp: false, creation_nonce: None })
        .unwrap();
    e.region_mark_as(&foreign, "catalogue", None).unwrap();

    let stores = e.store_filesystems().unwrap();
    let first = &stores[0];
    assert!(first.path.starts_with(&*e.data_dir().to_string_lossy()), "the data dir's first: {first:?}");
    let mut on_first = first.regions.clone();
    on_first.sort();
    let mut ab = vec![a.clone(), b.clone()];
    ab.sort();
    assert_eq!(on_first, ab, "A and B share the data dir's filesystem: one entry, both named");
    assert!(first.total_bytes > 0 && first.free_bytes <= first.total_bytes);
    assert!(stores.iter().all(|s| !s.regions.contains(&foreign)));
    match far {
        Some((_keep, c, o)) => {
            assert_eq!(stores.len(), 2, "{stores:?}");
            assert_eq!(stores[1].regions, vec![c]);
            assert!(stores[1].path.starts_with(&*o.to_string_lossy()), "{stores:?}");
        }
        None => assert_eq!(stores.len(), 1),
    }
}
