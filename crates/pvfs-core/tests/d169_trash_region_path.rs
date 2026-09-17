//! D169 — a delete that came through the view: THIS box's copy of a path in a
//! catalogue region goes to that region's trash — only when it is still the
//! file the caller saw, only a file, only in a region this box catalogues.

use std::path::Path;

use pvfs_core::{sync, BindSpec, Engine, HashPolicy, NodeSpec, TrashedHere, TYPE_FOLDER};

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
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

#[test]
fn this_boxs_copy_goes_to_its_regions_trash_only_if_it_is_the_file_that_was_seen() {
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");
    let ep = "TV/Show/Season 01/Show - s01e01.mkv";
    write(&lib, ep, b"the copy an upgrade replaces");
    write(&lib, "TV/Show/Season 01/Show - s01e02.mkv", b"its neighbour");

    let (mut e, _) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let r = folder(&mut e, "Library");
    e.region_mark_as(&r, "catalogue", None).unwrap();
    e.bind_folder(
        &r,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&r), None, 0).unwrap();
    let hash = e.view_entry(ep).unwrap().unwrap().content_hash.expect("hashed");
    let had_sidecar = sync::manifest_sidecar_path(&lib.join(ep)).is_file();

    // A region that is marked but that this box has bound nothing to.
    let elsewhere = folder(&mut e, "Elsewhere");
    e.region_mark_as(&elsewhere, "catalogue", None).unwrap();

    // ---- refusals move nothing
    assert_eq!(e.trash_region_path(&r, ep, &"00".repeat(32)).unwrap(), TrashedHere::Changed, "another hash");
    assert_eq!(e.trash_region_path(&elsewhere, ep, &hash).unwrap(), TrashedHere::NotHere);
    assert_eq!(e.trash_region_path(&"ab".repeat(32), ep, &hash).unwrap(), TrashedHere::NotHere, "no such region");
    assert!(e.trash_region_path(&r, "TV/Show/Season 01", &hash).is_err(), "a folder");
    for bad in ["", "../etc/passwd", "TV/../../x", "TV//x", "./TV"] {
        assert!(e.trash_region_path(&r, bad, &hash).is_err(), "{bad:?}");
    }
    assert!(lib.join(ep).is_file());
    assert!(sync::list_trash(&lib).is_empty());

    // ---- the file the caller saw: to the trash, its sidecar with it
    let TrashedHere::Trashed(to) = e.trash_region_path(&r, ep, &hash).unwrap() else {
        panic!("expected it trashed");
    };
    assert!(!lib.join(ep).exists());
    assert_eq!(std::fs::read(&to).unwrap(), b"the copy an upgrade replaces");
    assert!(to.starts_with(sync::trash_root(&lib)));
    assert_eq!(sync::manifest_sidecar_path(&to).is_file(), had_sidecar, "the sidecar travels with it");
    let listed: Vec<String> = sync::list_trash(&lib).into_iter().map(|t| t.rel_path).collect();
    assert_eq!(listed, vec![ep.to_string()], "and `pvfs trash ls` shows it (D167)");
    assert!(lib.join("TV/Show/Season 01/Show - s01e02.mkv").is_file(), "its neighbour is untouched");

    // ---- already gone is not an error: before the pass (row, no file) and after (no row)
    assert_eq!(e.trash_region_path(&r, ep, &hash).unwrap(), TrashedHere::Gone);
    e.scan_routed(Some(&r), None, 0).unwrap();
    assert!(e.view_entry(ep).unwrap().is_none(), "the next pass drops the row");
    assert_eq!(e.trash_region_path(&r, ep, &hash).unwrap(), TrashedHere::Gone);

    // ---- a file that changed on disk since the row was written (same hash in the row, another size)
    let ep2 = "TV/Show/Season 01/Show - s01e02.mkv";
    let h2 = e.view_entry(ep2).unwrap().unwrap().content_hash.unwrap();
    std::fs::write(lib.join(ep2), b"rewritten, and longer than it was").unwrap();
    assert_eq!(e.trash_region_path(&r, ep2, &h2).unwrap(), TrashedHere::Changed);
    assert!(lib.join(ep2).is_file());

    // ---- and it comes back the way anything in the trash does
    let back = sync::restore_from_trash(&lib, ep, None).unwrap();
    assert_eq!(back.restored, vec![ep.to_string()]);
    assert_eq!(std::fs::read(lib.join(ep)).unwrap(), b"the copy an upgrade replaces");
}
