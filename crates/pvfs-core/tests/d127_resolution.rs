//! D127 — resolution (doc 26 phase 4): a conflict is decided by a rule; a
//! draining region's losing or redundant copy drains away; a library
//! region's bytes never move.

use std::sync::atomic::AtomicBool;

use pvfs_core::media::Rules;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, ViewCopy, ViewEntry, ViewState, TYPE_FOLDER};

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

fn write(dir: &std::path::Path, rel: &str, bytes: &[u8], age_secs: u64) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, bytes).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(age_secs))
        .unwrap();
}

fn in_trash(root: &std::path::Path, rel: &str) -> bool {
    let trash = root.join(".pvfs-trash");
    std::fs::read_dir(&trash)
        .map(|days| days.flatten().any(|d| d.path().join(rel).exists()))
        .unwrap_or(false)
}

fn none_flag() -> AtomicBool {
    AtomicBool::new(false)
}

#[test]
fn a_draining_regions_copies_drain_away_and_a_librarys_never_move() {
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    let library = tmp.path().join("library");
    write(&staging, "Same/s.mkv", b"identical-bytes", 120);
    write(&library, "Same/s.mkv", b"identical-bytes", 120);
    write(&staging, "Lose/l.mkv", b"small-old", 120); // library's is bigger and newer
    write(&library, "Lose/l.mkv", &vec![b'L'; 4000], 10);
    write(&staging, "Win/w.mkv", &vec![b'W'; 4000], 10); // staging's is bigger and newer
    write(&library, "Win/w.mkv", b"small-old", 120);
    write(&staging, "Only/o.mkv", b"nowhere-else", 120);

    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let rs = region(&mut e, "Staging", &staging);
    let rl = region(&mut e, "Library", &library);
    e.set_region_drain(&rs, true).unwrap();
    assert!(e.region_drains(&rs).unwrap() && !e.region_drains(&rl).unwrap());

    // Dry run: says what would move, moves nothing.
    let dry = e.resolve_conflicts(&Rules::default(), true, &none_flag()).unwrap();
    assert_eq!(
        dry.trashed,
        vec![("Lose/l.mkv".to_string(), rs.clone()), ("Same/s.mkv".to_string(), rs.clone())]
    );
    assert_eq!(dry.kept_winners, vec!["Win/w.mkv".to_string()]);
    assert!(staging.join("Lose/l.mkv").exists() && staging.join("Same/s.mkv").exists());

    // The real pass: the redundant and the losing copies go to the STAGING
    // region's trash; its winner stays; the library is untouched; the
    // one-sided file stays (nothing to drain into).
    let rep = e.resolve_conflicts(&Rules::default(), false, &none_flag()).unwrap();
    assert_eq!(rep.trashed.len(), 2);
    assert!(!staging.join("Same/s.mkv").exists() && in_trash(&staging, "Same/s.mkv"));
    assert!(!staging.join("Lose/l.mkv").exists() && in_trash(&staging, "Lose/l.mkv"));
    assert!(staging.join("Win/w.mkv").exists() && staging.join("Only/o.mkv").exists());
    for rel in ["Same/s.mkv", "Lose/l.mkv", "Win/w.mkv"] {
        assert!(library.join(rel).exists(), "library copy {rel} must never move");
    }
    assert!(!in_trash(&library, "Same/s.mkv"));

    // The staging region's next scan drops the rows and publishes a new head;
    // the view resolves itself except for the conflict it may not touch.
    let seq_before = e.region_snapshots(&rs).unwrap().last().unwrap().seq;
    e.scan_routed(Some(&rs), None, 0).unwrap();
    assert_eq!(e.region_snapshots(&rs).unwrap().last().unwrap().seq, seq_before + 1);
    let same = e.merged_view("Same").unwrap().remove(0);
    assert_eq!((same.state.clone(), same.copies, same.sources.len()), (ViewState::Admitted, 1, 1));
    let lose = e.merged_view("Lose").unwrap().remove(0);
    assert_eq!((lose.state.clone(), lose.copies), (ViewState::Admitted, 1));
    assert_eq!(
        e.view_conflicts().unwrap().iter().map(|v| v.rel_path.as_str()).collect::<Vec<_>>(),
        vec!["Win/w.mkv"],
        "the conflict the draining copy WON stays a conflict — the library's loser is not ours to touch"
    );

    // Idempotent.
    let again = e.resolve_conflicts(&Rules::default(), false, &none_flag()).unwrap();
    assert!(again.trashed.is_empty());
    assert_eq!(again.kept_winners, vec!["Win/w.mkv".to_string()]);
}

#[test]
fn library_regions_conflicts_move_nothing_and_are_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    write(&a, "x.mkv", b"version-a", 120);
    write(&b, "x.mkv", &vec![b'B'; 4000], 10);
    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    region(&mut e, "A", &a);
    region(&mut e, "B", &b);
    let rep = e.resolve_conflicts(&Rules::default(), false, &none_flag()).unwrap();
    assert!(rep.trashed.is_empty(), "bytes on a non-draining region are never touched (§7.2)");
    assert_eq!(rep.reported, vec!["x.mkv".to_string()]);
    assert!(a.join("x.mkv").exists() && b.join("x.mkv").exists());
}

#[test]
fn the_drain_flag_is_in_the_log_and_survives_a_replay() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    std::fs::create_dir_all(&a).unwrap();
    let data = tmp.path().join("forest");
    let (mut e, _mn) = Engine::init(&data).unwrap();
    let r = region(&mut e, "A", &a);
    e.set_region_drain(&r, true).unwrap();
    e.close().unwrap();
    std::fs::remove_file(data.join("index.db")).unwrap();
    let e = Engine::open(&data).unwrap();
    assert!(e.region_drains(&r).unwrap(), "folded back from RegionDrainSet on a full replay");
    assert!(!e.region_drains("not-a-region").unwrap());
}

#[test]
fn the_served_copy_follows_the_ladder() {
    let copy = |region: &str, size: u64, mtime: u64, hash: Option<&str>| ViewCopy {
        region: region.into(),
        kind: "file".into(),
        size_bytes: size,
        mtime_ms: mtime,
        content_hash: hash.map(str::to_string),
        quality: None,
    };
    let entry = |state: ViewState, sources: Vec<ViewCopy>| ViewEntry {
        rel_path: "x.mkv".into(),
        kind: "file".into(),
        size_bytes: 0,
        mtime_ms: 0,
        content_hash: None,
        quality: None,
        state,
        copies: 0,
        sources,
    };
    let rules = Rules::default();
    // Equal quality (none measured): the size rung decides.
    let e1 = entry(
        ViewState::ConflictHashes(vec!["a".into(), "b".into()]),
        vec![copy("r1", 100, 5, Some("a")), copy("r2", 100_000, 1, Some("b"))],
    );
    assert_eq!(Engine::served_copy(&e1, &rules).unwrap().region, "r2");
    // Comparable sizes: newest wins.
    let e2 = entry(
        ViewState::ConflictHashes(vec!["a".into(), "b".into()]),
        vec![copy("r1", 1000, 9, Some("a")), copy("r2", 1001, 1, Some("b"))],
    );
    assert_eq!(Engine::served_copy(&e2, &rules).unwrap().region, "r1");
    // Admitted: the first hashed copy by region id.
    let e3 = entry(ViewState::Admitted, vec![copy("r1", 1, 1, None), copy("r2", 1, 1, Some("a"))]);
    assert_eq!(Engine::served_copy(&e3, &rules).unwrap().region, "r2");
    assert!(Engine::served_copy(&entry(ViewState::Unhashed, vec![copy("r1", 1, 1, None)]), &rules).is_none());
    assert!(Engine::served_copy(&entry(ViewState::ConflictKind, vec![copy("r1", 1, 1, Some("a"))]), &rules).is_none());
}
