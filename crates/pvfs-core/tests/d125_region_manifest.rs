//! D125 item 4 — a catalogue region's manifest: canonical bytes, a hash the
//! log learns as the region's head, and a new seq only when something
//! changed.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, TYPE_FOLDER};

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

fn catalogue_forest(data: &std::path::Path, lib: &std::path::Path) -> (Engine, String) {
    let (mut e, _mn) = Engine::init(data).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = folder(&mut e, &root, "Library");
    e.region_mark(&region).unwrap();
    e.close().unwrap();
    {
        let c = rusqlite::Connection::open(data.join("index.db")).unwrap();
        c.execute(
            "UPDATE regions SET kind='catalogue', log_file=NULL, state_root=NULL WHERE node_id=?1",
            [&region],
        )
        .unwrap();
    }
    let mut e = Engine::open(data).unwrap();
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

fn kind_at(data: &std::path::Path, seq: u64) -> String {
    let c = rusqlite::Connection::open_with_flags(
        data.join("log.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    c.query_row("SELECT kind FROM events WHERE seq = ?1", [seq as i64], |r| r.get(0))
        .unwrap()
}

/// The format is the contract: two boxes with the same rows must produce
/// these exact bytes. Locked here so a "harmless" reformat is a failing test.
#[test]
fn the_manifest_is_exactly_these_bytes() {
    let row = |kind: &str, rel: &str, size: u64, mtime: u64, hash: Option<&str>| RegionEntry {
        rel_path: rel.into(),
        kind: kind.into(),
        size_bytes: size,
        mtime_ms: mtime,
        changed_ms: 999_999, // per-box: must not appear
        content_hash: hash.map(str::to_string),
        quality: None,
        seen_at: 123_456, // per-box: must not appear
    };
    let rows = vec![
        row("file", "a.mkv", 3, 1000, Some("ab")),
        row("dir", "sub", 0, 0, None),
        row("file", "sub/odd\tname.mkv", 5, 2000, None),
    ];
    let bytes = Engine::region_manifest_bytes("r1", 7, &rows);
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        "pvfs-region-manifest 1\nr1\n7\n\
         file\ta.mkv\t3\t1000\tab\t-\n\
         dir\tsub\t0\t0\t-\t-\n\
         file\tsub/odd\\tname.mkv\t5\t2000\t-\t-\n"
    );
}

/// A pass that changes the catalogue publishes a snapshot, writes the manifest
/// file, and tells the log exactly ONE thing about it — the head. A pass that
/// changes nothing publishes nothing.
#[test]
fn a_changed_catalogue_publishes_a_head_and_an_unchanged_one_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(lib.join("sub")).unwrap();
    std::fs::write(lib.join("a.mkv"), b"aaa").unwrap();
    let data = dir.path().join("forest");
    let (mut e, region) = catalogue_forest(&data, &lib);

    let tip = e.log_tip().unwrap();
    e.scan_routed(Some(&region), None, 0).unwrap();
    let snaps = e.region_snapshots(&region).unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!((snaps[0].seq, snaps[0].entries), (1, 2));
    let file = data.join("regions").join(&region).join("manifest.1");
    let bytes = std::fs::read(&file).expect("the manifest file is written beside the region's other files");
    assert_eq!(blake3::hash(&bytes).to_hex().as_str(), snaps[0].manifest_hash);
    assert_eq!(bytes, Engine::region_manifest_bytes(&region, 1, &e.region_entries(&region).unwrap()));
    assert_eq!(e.log_tip().unwrap(), tip + 1, "one event: the head");
    assert_eq!(kind_at(&data, tip + 1), "SubRegionHead");
    let info = e.region_info(&region).unwrap().unwrap();
    assert_eq!((info.committed_seq, info.committed_head.as_str()), (1, snaps[0].manifest_hash.as_str()));

    // Nothing changed: no snapshot, no event.
    e.scan_routed(Some(&region), None, 0).unwrap();
    assert_eq!(e.region_snapshots(&region).unwrap().len(), 1);
    assert_eq!(e.log_tip().unwrap(), tip + 1);

    // Something changed: seq 2, one more event, the head follows.
    std::fs::write(lib.join("sub").join("b.mkv"), b"bbbbb").unwrap();
    e.scan_routed(Some(&region), None, 0).unwrap();
    let snaps = e.region_snapshots(&region).unwrap();
    assert_eq!(snaps.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert_ne!(snaps[0].manifest_hash, snaps[1].manifest_hash);
    assert!(data.join("regions").join(&region).join("manifest.2").exists());
    assert_eq!(e.log_tip().unwrap(), tip + 2);
    assert_eq!(e.region_info(&region).unwrap().unwrap().committed_seq, 2);
}

/// Determinism across builds of the catalogue: dropping the rows and
/// re-scanning the same disk reproduces the same hash, and publishes no new
/// seq for it.
#[test]
fn the_same_disk_hashes_the_same_however_the_rows_got_there() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(lib.join("empty")).unwrap();
    std::fs::write(lib.join("a.mkv"), b"aaa").unwrap();
    let data = dir.path().join("forest");
    let (mut e, region) = catalogue_forest(&data, &lib);
    e.scan_routed(Some(&region), None, 0).unwrap();
    let first = e.region_snapshots(&region).unwrap().remove(0);
    e.close().unwrap();
    {
        let c = rusqlite::Connection::open(data.join("index.db")).unwrap();
        c.execute("DELETE FROM region_entries WHERE region_id=?1", [&region]).unwrap();
    }
    let mut e = Engine::open(&data).unwrap();
    e.scan_routed(Some(&region), None, 0).unwrap();
    let snaps = e.region_snapshots(&region).unwrap();
    assert_eq!(snaps, vec![first], "same rows, same hash, no new seq");
}
