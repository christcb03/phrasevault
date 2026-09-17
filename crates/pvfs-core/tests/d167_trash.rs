//! D167 — what automated deletions moved aside can be listed and put back:
//! `sync::list_trash`, `sync::restore_from_trash`, `Engine::region_trash_lists`
//! (what `pvfs trash ls` and `pvfs trash restore` are thin over).

use std::path::Path;

use pvfs_core::{sync, BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

/// As `move_to_trash_with_sidecar` leaves it, on a day of our choosing.
fn trashed(root: &Path, day: u64, rel: &str, bytes: &[u8]) {
    let at = sync::trash_root(root).join(day.to_string()).join(rel);
    write(root, at.strip_prefix(root).unwrap().to_str().unwrap(), bytes);
    std::fs::write(sync::manifest_sidecar_path(&at), b"sidecar").unwrap();
}

#[test]
fn the_trash_is_listed_and_a_file_or_a_folder_goes_back_never_over_another() {
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");
    write(&lib, "TV/Show/Season 01/Show - s01e02.mkv", b"the upgrade that replaced it");
    trashed(&lib, 20_710, "TV/Show/Season 01/Show - s01e01.mkv", b"one");
    trashed(&lib, 20_710, "TV/Show/Season 01/Show - s01e02.mkv", b"the copy it replaced");
    trashed(&lib, 20_712, "TV/Show/Season 01/Show - s01e01.mkv", b"one, again, newer");
    trashed(&lib, 20_712, "Movies/Film (2001)/Film (2001).mkv", b"film");

    // ---- ls: newest day first; sidecars travel unlisted
    let all = sync::list_trash(&lib);
    let shown: Vec<(u64, &str, u64)> = all.iter().map(|e| (e.day, e.rel_path.as_str(), e.size_bytes)).collect();
    assert_eq!(
        shown,
        vec![
            (20_712, "Movies/Film (2001)/Film (2001).mkv", 4),
            (20_712, "TV/Show/Season 01/Show - s01e01.mkv", 17),
            (20_710, "TV/Show/Season 01/Show - s01e01.mkv", 3),
            (20_710, "TV/Show/Season 01/Show - s01e02.mkv", 20),
        ]
    );

    // ---- through the engine: the bound folder, its retention, its entries
    let (mut e, _) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let r = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Library".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
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
    let lists = e.region_trash_lists().unwrap();
    assert_eq!(lists.len(), 1);
    assert_eq!((lists[0].region.as_str(), lists[0].label.as_str(), lists[0].root.as_path()), (r.as_str(), "Library", lib.as_path()));
    assert_eq!(lists[0].retention_days, sync::TRASH_KEEP_DAYS_DEFAULT);
    assert!(!lists[0].drains);
    assert_eq!(lists[0].entries, all);
    assert!(e.view_entry("Movies/Film (2001)/Film (2001).mkv").unwrap().is_none(), "premise: the trash is not content");

    // ---- a file goes back, its sidecar with it, and is catalogued again
    let done = sync::restore_from_trash(&lib, "Movies/Film (2001)/Film (2001).mkv", None).unwrap();
    assert_eq!(done.restored, vec!["Movies/Film (2001)/Film (2001).mkv"]);
    assert!(done.in_the_way.is_empty());
    let film = lib.join("Movies/Film (2001)/Film (2001).mkv");
    assert_eq!(std::fs::read(&film).unwrap(), b"film");
    assert!(sync::manifest_sidecar_path(&film).is_file(), "the sidecar came back with it");
    assert!(!sync::trash_root(&lib).join("20712/Movies").exists(), "the folders it emptied are tidied");
    e.scan_routed(Some(&r), None, 0).unwrap();
    assert!(e.view_entry("Movies/Film (2001)/Film (2001).mkv").unwrap().is_some(), "content again on the next pass");

    // ---- a folder: every file under it, the newest of each — but never over a file that is there
    let done = sync::restore_from_trash(&lib, "TV/Show", None).unwrap();
    assert_eq!(done.restored, vec!["TV/Show/Season 01/Show - s01e01.mkv"]);
    assert_eq!(done.in_the_way, vec!["TV/Show/Season 01/Show - s01e02.mkv"]);
    assert_eq!(std::fs::read(lib.join("TV/Show/Season 01/Show - s01e01.mkv")).unwrap(), b"one, again, newer");
    assert_eq!(std::fs::read(lib.join("TV/Show/Season 01/Show - s01e02.mkv")).unwrap(), b"the upgrade that replaced it");
    let left: Vec<(u64, String)> = sync::list_trash(&lib).into_iter().map(|e| (e.day, e.rel_path)).collect();
    assert_eq!(
        left,
        vec![
            (20_710, "TV/Show/Season 01/Show - s01e01.mkv".to_string()),
            (20_710, "TV/Show/Season 01/Show - s01e02.mkv".to_string()),
        ],
        "what was in the way, and the older day's copy, are still in the trash"
    );

    // ---- a named day; and what is not there is an error, not a silence
    std::fs::remove_file(lib.join("TV/Show/Season 01/Show - s01e02.mkv")).unwrap();
    let done = sync::restore_from_trash(&lib, "TV/Show/Season 01/Show - s01e02.mkv", Some(20_710)).unwrap();
    assert_eq!(done.restored.len(), 1);
    assert_eq!(std::fs::read(lib.join("TV/Show/Season 01/Show - s01e02.mkv")).unwrap(), b"the copy it replaced");
    assert!(sync::restore_from_trash(&lib, "TV/Show/Season 01/Show - s01e02.mkv", None).is_err());
    assert!(sync::restore_from_trash(&lib, "TV/Show", Some(19_000)).is_err());
    for bad in ["", "/", "../outside", "TV/../../etc"] {
        assert!(sync::restore_from_trash(&lib, bad, None).is_err(), "{bad:?}");
    }
}

/// D170 — one delete through the view trashes the same file in every region
/// that held it; a restore brings every IDENTICAL copy back, and leaves a
/// different file at that path (an older encode `resolve` retired) alone.
#[test]
fn a_restore_brings_back_every_identical_copy_and_leaves_a_different_file_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let (lib, ext, old) = (tmp.path().join("lib"), tmp.path().join("ext"), tmp.path().join("old"));
    for r in [&lib, &ext, &old] {
        std::fs::create_dir_all(r).unwrap();
    }
    let ep1 = "TV/Show/Season 01/e1.mkv";
    let ep2 = "TV/Show/Season 01/e2.mkv";
    // e1: the same bytes in lib (today) and ext (two days ago — drained then); another file in old
    trashed(&lib, 20_712, ep1, b"the episode");
    trashed(&ext, 20_710, ep1, b"the episode");
    trashed(&old, 20_711, ep1, b"an older encode of it");
    // e2: only lib has it — nothing is read, nothing is asked
    trashed(&lib, 20_712, ep2, b"two");
    // a path deleted while it was a CONFLICT: two different files, the same day — both were that delete
    trashed(&lib, 20_712, "Movies/F/f.mkv", b"version a");
    trashed(&ext, 20_712, "Movies/F/f.mkv", b"version b");

    let roots = [lib.as_path(), ext.as_path(), old.as_path()];
    let done = sync::restore_identical(&roots, "TV/Show", None).unwrap();
    assert_eq!(done.per_root[0].restored, vec![ep1.to_string(), ep2.to_string()]);
    assert_eq!(done.per_root[1].restored, vec![ep1.to_string()], "the identical copy, though trashed on another day");
    assert!(done.per_root[2].restored.is_empty());
    assert_eq!(done.different, vec![(2, ep1.to_string())], "the older encode is left, and named");
    assert_eq!(std::fs::read(ext.join(ep1)).unwrap(), b"the episode");
    assert!(!old.join(ep1).exists());
    assert_eq!(sync::list_trash(&old).len(), 1, "still in its trash");

    let done = sync::restore_identical(&roots, "Movies/F/f.mkv", None).unwrap();
    assert_eq!(std::fs::read(lib.join("Movies/F/f.mkv")).unwrap(), b"version a");
    assert_eq!(std::fs::read(ext.join("Movies/F/f.mkv")).unwrap(), b"version b");
    assert!(done.different.is_empty());

    assert!(sync::restore_identical(&roots, "TV/Nothing", None).is_err());
    assert!(sync::restore_identical(&roots, "../x", None).is_err());
}
