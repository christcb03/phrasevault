//! D169 — `unlink` through the view mount: a file in a region this box
//! catalogues goes to that region's trash and is gone from the mount AT ONCE
//! (before any pass has told the catalogue); a file whose holder cannot be
//! asked is an error that hides nothing; a write is still refused (renames
//! and folders: D170, `d170_view_rename.rs`). The other-box path is
//! `pvfsd/tests/d169_trash_path.rs` and the lab pair.

use pvfs_client::hash_cache::CacheOpts;
use pvfs_core::acl::Principal;
use pvfs_core::{crypto, identity, sync, BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, TYPE_FOLDER};

fn fuse_available() -> bool {
    std::path::Path::new("/dev/fuse").exists()
        && std::process::Command::new("sh")
            .args(["-c", "command -v fusermount3 || command -v fusermount"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

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

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|d| d.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn a_delete_through_the_mount_is_a_trip_to_the_trash_and_the_path_is_gone_at_once() {
    if !fuse_available() {
        eprintln!("skipping: no /dev/fuse or fusermount on this host");
        return;
    }
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");
    for (rel, bytes) in [
        ("TV/Show/Season 01/Show - s01e01.mkv", &b"the copy an upgrade replaces"[..]),
        ("TV/Show/Season 01/Show - s01e02.mkv", &b"its neighbour"[..]),
    ] {
        std::fs::create_dir_all(lib.join(rel).parent().unwrap()).unwrap();
        std::fs::write(lib.join(rel), bytes).unwrap();
    }

    let (mut e, mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let r = folder(&mut e, &root, "Library");
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

    // A region another box catalogues: its row is here, its holder is not.
    let other_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let other_pub = crypto::pubkey_bytes(&other_key);
    e.authorize_member(&mn, &other_pub).unwrap();
    let far = folder(&mut e, &root, "Far");
    e.region_mark_as(&far, "catalogue", Some(&Principal::Key(other_pub.clone()))).unwrap();
    let row = |rel: &str, kind: &str, size: u64, hash: Option<String>| RegionEntry {
        rel_path: rel.into(),
        kind: kind.into(),
        size_bytes: size,
        mtime_ms: 1,
        changed_ms: 1,
        content_hash: hash,
        quality: None,
        seen_at: 0,
    };
    let rows = vec![
        row("Movies", "dir", 0, None),
        row("Movies/far.mkv", "file", 9, Some(blake3::hash(b"far bytes").to_hex().to_string())),
    ];
    let manifest = Engine::region_manifest_bytes(&far, 1, &rows);
    let prep = e
        .prepare_commit_region_head(&other_pub, &far, 1, blake3::hash(&manifest).to_hex().as_str())
        .unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(&other_key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
    e.install_region_snapshot(&far, 1, &manifest, "test").unwrap();
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();

    let mnt = tempfile::tempdir().unwrap();
    // No box to ask: the far file's delete must fail and hide nothing.
    let session = pvfs_fuse::spawn_view_mount_with(&data_dir, mnt.path(), CacheOpts::default(), Some(Vec::new())).unwrap();

    let season = mnt.path().join("TV/Show/Season 01");
    assert_eq!(names(&season), vec!["Show - s01e01.mkv", "Show - s01e02.mkv"]);

    // ---- a file this box holds: deleted through the mount
    std::fs::remove_file(season.join("Show - s01e01.mkv")).expect("the delete succeeds");
    assert!(!lib.join("TV/Show/Season 01/Show - s01e01.mkv").exists(), "the file left the library");
    let trashed: Vec<String> = sync::list_trash(&lib).into_iter().map(|t| t.rel_path).collect();
    assert_eq!(trashed, vec!["TV/Show/Season 01/Show - s01e01.mkv"], "and is in the region's trash, restorable");
    // No pass has run: the catalogue still lists the row. The mount does not.
    let still_listed = Engine::open(&data_dir).unwrap();
    assert!(still_listed.view_entry("TV/Show/Season 01/Show - s01e01.mkv").unwrap().is_some(), "premise: the catalogue has not caught up");
    still_listed.close().unwrap();
    assert_eq!(names(&season), vec!["Show - s01e02.mkv"], "gone from the mount at once");
    assert!(std::fs::metadata(season.join("Show - s01e01.mkv")).is_err());
    assert!(std::fs::remove_file(season.join("Show - s01e01.mkv")).is_err(), "and deleting it again is 'no such file'");

    // ---- a file only another box holds, and nobody to ask: an error, nothing hidden
    assert!(std::fs::remove_file(mnt.path().join("Movies/far.mkv")).is_err());
    assert_eq!(names(&mnt.path().join("Movies")), vec!["far.mkv"]);

    // ---- bytes still do not come through the view, and a folder with a file in it stays
    assert!(std::fs::remove_dir(&season).is_err());
    assert!(std::fs::write(season.join("new.mkv"), b"x").is_err());
    assert_eq!(std::fs::read(season.join("Show - s01e02.mkv")).unwrap(), b"its neighbour");

    // ---- restored from the trash, it comes back — the tombstone must not
    // outlive the delete. Nobody lists the folder in between, so the mount
    // never SEES the path gone; what tells it is that the region has
    // published again (twice: without the file, then with it) and lists it.
    let mut scanner = Engine::open(&data_dir).unwrap();
    scanner.scan_routed(Some(&r), None, 0).unwrap();
    assert!(scanner.view_entry("TV/Show/Season 01/Show - s01e01.mkv").unwrap().is_none(), "the pass dropped the row");
    let back = sync::restore_from_trash(&lib, "TV/Show/Season 01/Show - s01e01.mkv", None).unwrap();
    assert_eq!(back.restored.len(), 1);
    scanner.scan_routed(Some(&r), None, 0).unwrap();
    assert!(scanner.view_entry("TV/Show/Season 01/Show - s01e01.mkv").unwrap().is_some(), "and the next one has it again, same hash");
    scanner.close().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(6)); // the mount's 5 s listing cache
    assert_eq!(names(&season), vec!["Show - s01e01.mkv", "Show - s01e02.mkv"], "a restored file is not hidden by the memory of its delete");
    assert_eq!(std::fs::read(season.join("Show - s01e01.mkv")).unwrap(), b"the copy an upgrade replaces");
    drop(session);
}
