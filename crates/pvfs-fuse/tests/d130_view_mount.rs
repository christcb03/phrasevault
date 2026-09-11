//! D130 item 3 — the merged view as a filesystem: the union is listed, an
//! admitted file reads its bytes, a conflict reads the ladder winner's, an
//! unhashed file is absent, and a row whose bytes are nowhere fails to open
//! while the listing stays answerable.

use std::time::Duration;

use pvfs_core::acl::Principal;
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, TYPE_FOLDER};

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

fn region(e: &mut Engine, label: &str, dir: &std::path::Path, policy: HashPolicy) -> String {
    let root = e.identity.root_node_id.clone();
    let r = folder(e, &root, label);
    e.region_mark_as(&r, "catalogue", None).unwrap();
    e.bind_folder(
        &r,
        BindSpec {
            source_uri: format!("file://{}", dir.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: policy,
        },
    )
    .unwrap();
    e.scan_routed(Some(&r), None, 0).unwrap();
    r
}

fn write(dir: &std::path::Path, rel: &str, bytes: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
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
fn the_view_mount_lists_the_union_and_serves_admitted_bytes() {
    if !fuse_available() {
        eprintln!("skipping: no /dev/fuse or fusermount on this host");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    let c = tmp.path().join("c");
    write(&a, "Movies/Same (2001)/same.mkv", b"identical bytes");
    write(&b, "Movies/Same (2001)/same.mkv", b"identical bytes");
    write(&a, "Movies/Differs (2002)/differs.mkv", b"version-a");
    write(&b, "Movies/Differs (2002)/differs.mkv", b"version-b, longer");
    write(&a, "Movies/Only A (2003)/only.mkv", b"only-a");
    std::fs::create_dir_all(b.join("Movies/Empty (2004)")).unwrap();
    write(&c, "Movies/Never (2005)/never.mkv", b"never hashed");
    // The differing copies: B's is larger and newer, the ladder's winner.
    std::fs::File::options()
        .write(true)
        .open(a.join("Movies/Differs (2002)/differs.mkv"))
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(60))
        .unwrap();

    let (mut e, mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let _ra = region(&mut e, "A", &a, HashPolicy::OnAdd);
    let _rb = region(&mut e, "B", &b, HashPolicy::OnAdd);
    let _rc = region(&mut e, "C", &c, HashPolicy::Never);

    // A region another box catalogues, with a file whose bytes are nowhere
    // reachable from here (no announced endpoints).
    let holder_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let holder_pub = crypto::pubkey_bytes(&holder_key);
    e.authorize_member(&mn, &holder_pub).unwrap();
    let root = e.identity.root_node_id.clone();
    let far = folder(&mut e, &root, "Far");
    e.region_mark_as(&far, "catalogue", Some(&Principal::Key(holder_pub.clone()))).unwrap();
    let h_far = blake3::hash(b"far away bytes").to_hex().to_string();
    let rows = vec![
        RegionEntry { rel_path: "Movies".into(), kind: "dir".into(), size_bytes: 0, mtime_ms: 1, changed_ms: 1, content_hash: None, quality: None, seen_at: 0 },
        RegionEntry { rel_path: "Movies/Far (2006)".into(), kind: "dir".into(), size_bytes: 0, mtime_ms: 1, changed_ms: 1, content_hash: None, quality: None, seen_at: 0 },
        RegionEntry { rel_path: "Movies/Far (2006)/far.mkv".into(), kind: "file".into(), size_bytes: 14, mtime_ms: 1, changed_ms: 1, content_hash: Some(h_far), quality: None, seen_at: 0 },
    ];
    let bytes = Engine::region_manifest_bytes(&far, 1, &rows);
    let prep = e
        .prepare_commit_region_head(&holder_pub, &far, 1, blake3::hash(&bytes).to_hex().as_str())
        .unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(&holder_key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
    e.install_region_snapshot(&far, 1, &bytes, "test").unwrap();
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();

    let mnt = tempfile::tempdir().unwrap();
    let session = pvfs_fuse::spawn_view_mount(&data_dir, mnt.path()).unwrap();

    // The union, one level at a time; the unhashed region's file is absent.
    assert_eq!(names(mnt.path()), vec!["Movies"]);
    assert_eq!(
        names(&mnt.path().join("Movies")),
        vec!["Differs (2002)", "Empty (2004)", "Far (2006)", "Never (2005)", "Only A (2003)", "Same (2001)"]
    );
    assert!(names(&mnt.path().join("Movies/Never (2005)")).is_empty(), "an unhashed file is not admitted");
    assert!(names(&mnt.path().join("Movies/Empty (2004)")).is_empty());
    let same = mnt.path().join("Movies/Same (2001)/same.mkv");
    assert_eq!(std::fs::metadata(&same).unwrap().len(), 15);
    assert_eq!(std::fs::read(&same).unwrap(), b"identical bytes");
    assert_eq!(std::fs::read(mnt.path().join("Movies/Only A (2003)/only.mkv")).unwrap(), b"only-a");
    // A conflict reads the served copy (the ladder winner).
    let differs = mnt.path().join("Movies/Differs (2002)/differs.mkv");
    assert_eq!(std::fs::read(&differs).unwrap(), b"version-b, longer");
    // Bytes nowhere: the entry is listed, the open is refused within the
    // bound, and the listing keeps answering.
    let far_file = mnt.path().join("Movies/Far (2006)/far.mkv");
    assert_eq!(std::fs::metadata(&far_file).unwrap().len(), 14);
    let started = std::time::Instant::now();
    assert!(std::fs::read(&far_file).is_err(), "no holder anywhere: the read fails");
    assert!(started.elapsed() < Duration::from_secs(150), "and fails within the read bound");
    assert_eq!(names(mnt.path()), vec!["Movies"], "the mount is still answering");
    assert!(std::fs::remove_file(&same).is_err(), "the view is read-only, namespace included");
    drop(session);
}
