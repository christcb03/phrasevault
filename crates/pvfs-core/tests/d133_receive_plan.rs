//! D133 items 0-1 — the receiving side's declarations and its plan over the
//! merged view (doc 26 §7.3), on one box with several catalogue regions.

use pvfs_core::media::Rules;
use pvfs_core::{sync, BindSpec, Engine, HashPolicy, NodeSpec, ViewState, TYPE_FOLDER};

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

fn region(e: &mut Engine, label: &str, dir: &std::path::Path) -> String {
    let root = e.identity.root_node_id.clone();
    let r = folder(e, &root, label);
    e.region_mark_as(&r, "catalogue", None).unwrap();
    std::fs::create_dir_all(dir).unwrap();
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
    e.scan_routed(Some(&r), None, 0).unwrap();
    r
}

fn write(dir: &std::path::Path, rel: &str, bytes: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

#[test]
fn declarations_round_trip_with_defaults() {
    let tmp = tempfile::tempdir().unwrap();
    let (e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let d = e.data_dir().to_path_buf();
    e.close().unwrap();
    let r = "ab".repeat(32);
    assert!(sync::receiving_regions(&d).unwrap().is_empty());
    assert_eq!(sync::region_retention_days(&d, &r).unwrap(), sync::TRASH_KEEP_DAYS_DEFAULT);
    sync::set_region_receive(&d, &r, true).unwrap();
    sync::set_region_retention(&d, &r, 0).unwrap();
    assert_eq!(sync::receiving_regions(&d).unwrap(), vec![r.clone()]);
    assert_eq!(sync::region_retention_days(&d, &r).unwrap(), 0);
    sync::set_region_receive(&d, &r, true).unwrap(); // idempotent, one row
    assert_eq!(sync::receiving_regions(&d).unwrap().len(), 1);
    sync::set_region_receive(&d, &r, false).unwrap();
    assert!(sync::receiving_regions(&d).unwrap().is_empty());
    // the older placement lines survive beside the new ones
    let text = std::fs::read_to_string(sync::placement_path(&d)).unwrap();
    assert!(text.contains(&format!("retention {r} 0")), "{text}");
}

#[test]
fn the_plan_follows_the_table() {
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    let lib = tmp.path().join("lib");
    // staging-only file; an agreeing pair; a conflict staging wins (bigger);
    // a conflict the library wins; an unsafe path is never planned.
    write(&staging, "Movies/New (2024)/new.mkv", b"new-bytes");
    write(&staging, "Movies/Same (2001)/same.mkv", b"same");
    write(&lib, "Movies/Same (2001)/same.mkv", b"same");
    write(&staging, "Movies/Up (2002)/up.mkv", b"upgraded-much-larger-bytes");
    write(&lib, "Movies/Up (2002)/up.mkv", b"small");
    write(&staging, "Movies/Old (2003)/old.mkv", b"tiny");
    write(&lib, "Movies/Old (2003)/old.mkv", b"the-library-has-the-bigger-one");
    // make the library's "Up" copy older so recency does not mask size
    for (root, rel) in [(&lib, "Movies/Up (2002)/up.mkv"), (&staging, "Movies/Old (2003)/old.mkv")] {
        std::fs::File::options()
            .write(true)
            .open(root.join(rel))
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(120))
            .unwrap();
    }

    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let rs = region(&mut e, "Staging", &staging);
    let rl = region(&mut e, "Library", &lib);
    e.set_region_drain(&rs, true).unwrap();

    // Nobody receives: the plan is empty however the view looks.
    let (items, _) = e.receive_plan(&Rules::default()).unwrap();
    assert!(items.is_empty());

    sync::set_region_receive(e.data_dir(), &rl, true).unwrap();
    let roots = e.receiving_roots().unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].0, rl);
    assert_eq!(roots[0].1, lib);

    let (items, skips) = e.receive_plan(&Rules::default()).unwrap();
    let by_path: std::collections::HashMap<&str, &pvfs_core::ReceiveItem> =
        items.iter().map(|i| (i.rel_path.as_str(), i)).collect();
    let new = by_path.get("Movies/New (2024)/new.mkv").expect("staging-only is received");
    assert!(!new.replaces);
    assert_eq!(new.from_region, rs);
    assert_eq!((new.dest_region.as_str(), new.dest_root.as_path()), (rl.as_str(), lib.as_path()));
    assert_eq!(new.hash, blake3::hash(b"new-bytes").to_hex().to_string());
    assert_eq!(new.size_bytes, 9);
    let up = by_path.get("Movies/Up (2002)/up.mkv").expect("a staging winner replaces the library copy");
    assert!(up.replaces);
    assert_eq!(up.dest_region, rl);
    assert!(!by_path.contains_key("Movies/Same (2001)/same.mkv"), "an agreeing pair needs nothing");
    assert!(!by_path.contains_key("Movies/Old (2003)/old.mkv"), "the library's winner stays; D127 drains the loser");
    assert_eq!(items.len(), 2, "{items:?}");
    assert!(skips.is_empty(), "{skips:?}");

    // The view agrees with the plan's reading of the conflicts.
    let conflicts = e.view_conflicts().unwrap();
    assert_eq!(conflicts.len(), 2);
    assert!(conflicts.iter().all(|c| matches!(c.state, ViewState::ConflictHashes(_))));
    e.close().unwrap();
}

#[test]
fn unsafe_paths_are_refused_and_the_fullest_disk_is_not_chosen() {
    assert!(Engine::safe_rel_path("Movies/A (2001)/a.mkv"));
    assert!(!Engine::safe_rel_path("../etc/passwd"));
    assert!(!Engine::safe_rel_path("Movies/../../x"));
    assert!(!Engine::safe_rel_path("/abs"));
    assert!(!Engine::safe_rel_path("Movies//x"));
    assert!(!Engine::safe_rel_path(".pvfs-trash/x"));
    assert!(!Engine::safe_rel_path("Movies/.pvfs-incoming/x"));
    assert!(!Engine::safe_rel_path(""));

    // Two receiving regions on one filesystem tie on free space; the tie
    // breaks on region id, so the choice is deterministic.
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let ra = region(&mut e, "A", &a);
    let rb = region(&mut e, "B", &b);
    sync::set_region_receive(e.data_dir(), &ra, true).unwrap();
    sync::set_region_receive(e.data_dir(), &rb, true).unwrap();
    let roots = e.receiving_roots().unwrap();
    assert_eq!(roots.len(), 2);
    let mut ids: Vec<&str> = roots.iter().map(|(r, _)| r.as_str()).collect();
    ids.sort();
    assert_eq!(roots[0].0, ids[0], "same free space: lowest region id first");
    e.close().unwrap();
}
