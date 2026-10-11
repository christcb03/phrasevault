//! PVOS D235 — two of D218's PVFS findings, closed in the core.
//!
//! - A region manifest's rows name files and places on this box's disk: a
//!   row's hash became `receive`'s `<hash>.partial`, its path a path under a
//!   root. A manifest whose row says otherwise is refused whole.
//! - A root that cannot show its `.pvfs-root` marker may be an unmounted
//!   volume's empty mountpoint: writers (a create through the view,
//!   `receive`) leave it out, so the next watch never adopts a system-disk
//!   file there and sweeps the region's rows.

use pvfs_core::{sync, BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, TYPE_FOLDER};

fn row(kind: &str, rel: &str, hash: Option<&str>) -> RegionEntry {
    RegionEntry {
        rel_path: rel.into(),
        kind: kind.into(),
        size_bytes: 3,
        mtime_ms: 1_700_000_000_000,
        changed_ms: 1_700_000_000_000,
        content_hash: hash.map(str::to_string),
        quality: None,
        seen_at: 0,
    }
}

fn parse(rows: &[RegionEntry]) -> Result<Vec<RegionEntry>, String> {
    let bytes = Engine::region_manifest_bytes(&"ab".repeat(32), 1, rows);
    Engine::parse_region_manifest(&bytes).map(|(_, _, r)| r).map_err(|e| e.to_string())
}

#[test]
fn a_manifest_row_that_could_name_a_place_off_its_root_is_refused() {
    let good = "0f".repeat(32);
    let ok = parse(&[
        row("dir", "Movies", None),
        row("file", "Movies/Film (2001)/Film (2001).mkv", Some(&good)),
        row("file", "Movies/.hidden but fine.nfo", None),
    ])
    .expect("a good manifest parses");
    assert_eq!(ok.len(), 3);

    for (what, bad) in [
        ("a hash that is a path", row("file", "a.mkv", Some("../../../home/chris/x"))),
        ("an upper-case hash", row("file", "a.mkv", Some(&"0F".repeat(32)))),
        ("a short hash", row("file", "a.mkv", Some("abc"))),
        ("a long hash", row("file", "a.mkv", Some(&"0f".repeat(33)))),
        ("a kind that is neither", row("link", "a.mkv", Some(&good))),
        ("a `..` part", row("file", "Movies/../../etc/passwd", Some(&good))),
        ("a leading `/`", row("file", "/etc/passwd", Some(&good))),
        ("an empty part", row("file", "Movies//a.mkv", Some(&good))),
        ("a `.` part", row("file", "./a.mkv", Some(&good))),
    ] {
        let err = parse(&[row("dir", "Movies", None), bad]).expect_err(what);
        assert!(err.contains("row 2"), "{what}: the refusal names the row: {err}");
    }
    assert!(Engine::is_content_hash(&good));
    assert!(!Engine::is_content_hash("../x"));
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

#[test]
fn a_root_without_its_marker_takes_no_new_files() {
    let tmp = tempfile::tempdir().unwrap();
    let (mounted, gone) = (tmp.path().join("mounted"), tmp.path().join("gone"));
    let (mut e, _mn) = Engine::init(&tmp.path().join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();
    let mut ids = Vec::new();
    for (label, dir) in [("Mounted", &mounted), ("Gone", &gone)] {
        std::fs::create_dir_all(dir).unwrap();
        let r = folder(&mut e, &root, label);
        e.region_mark_as(&r, "catalogue", None).unwrap();
        e.bind_folder(
            &r,
            BindSpec {
                source_uri: format!("file://{}", dir.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
        sync::set_region_receive(e.data_dir(), &r, true).unwrap();
        ids.push(r);
    }
    let both = |v: Vec<(String, std::path::PathBuf)>| v.into_iter().map(|(r, _)| r).collect::<std::collections::BTreeSet<_>>();
    let all: std::collections::BTreeSet<String> = ids.iter().cloned().collect();
    assert_eq!(both(e.writable_roots().unwrap()), all, "both marked: both take files");
    assert_eq!(both(e.receiving_roots().unwrap()), all);

    // The volume behind `gone` is not mounted: its mountpoint is empty.
    std::fs::remove_file(gone.join(sync::ROOT_MARKER)).unwrap();
    assert!(!sync::root_marker_present(&gone));
    let only: std::collections::BTreeSet<String> = [ids[0].clone()].into_iter().collect();
    assert_eq!(both(e.writable_roots().unwrap()), only, "a create never lands in an empty mountpoint");
    assert_eq!(both(e.receiving_roots().unwrap()), only, "nor does receive");
    // and nothing was written there by asking
    assert_eq!(std::fs::read_dir(&gone).unwrap().count(), 0);

    // mounted again (the marker is back): it takes files again
    sync::write_root_marker(&gone, &e.identity.forest_id).unwrap();
    assert_eq!(both(e.writable_roots().unwrap()), all);
    e.close().unwrap();
}
