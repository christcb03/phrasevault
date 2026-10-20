//! PVOS D255 — every file the merged view holds more than once, for the
//! dashboard's "multiple copies" card. Settled: two copies in regions that do
//! not drain (the card's number). In flight: a staging copy beside another
//! (the drain at work). Stale: more than one copy only with a superseded
//! snapshot counted.

use pvfs_core::{copies_row, BindSpec, CopiesKind, Engine, HashPolicy, NodeSpec, ViewCopy, ViewEntry, ViewState, TYPE_FOLDER};

fn region(e: &mut Engine, label: &str, dir: &std::path::Path) -> String {
    let root = e.identity.root_node_id.clone();
    let r = e
        .add_node(
            &root,
            NodeSpec { node_type: TYPE_FOLDER.into(), label: label.into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
        )
        .unwrap();
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

fn write(dir: &std::path::Path, rel: &str, bytes: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, bytes).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(120))
        .unwrap();
}

#[test]
fn the_view_says_which_files_it_holds_more_than_once_and_how() {
    let tmp = tempfile::tempdir().unwrap();
    let (local, nas, staging) = (tmp.path().join("local"), tmp.path().join("nas"), tmp.path().join("staging"));
    // Settled and identical: the same film on two library disks.
    write(&local, "Movies/Twice (2020)/Twice.mkv", &vec![b'T'; 3000]);
    write(&nas, "Movies/Twice (2020)/Twice.mkv", &vec![b'T'; 3000]);
    // Settled and different: two cuts of one episode on two library disks.
    write(&local, "TV/Show/S01E01.mkv", &vec![b'A'; 1000]);
    write(&nas, "TV/Show/S01E01.mkv", &vec![b'B'; 1500]);
    // In flight: staging's copy waiting to drain beside the library's.
    write(&staging, "Movies/Arriving (2026)/Arriving.mkv", &vec![b'N'; 2000]);
    write(&nas, "Movies/Arriving (2026)/Arriving.mkv", &vec![b'N'; 2000]);
    // Once: not a row.
    write(&local, "Movies/Once (1999)/Once.mkv", b"only here");

    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    region(&mut e, "Local", &local);
    region(&mut e, "Nas", &nas);
    let rs = region(&mut e, "Staging", &staging);
    e.set_region_drain(&rs, true).unwrap();

    let c = e.view_copies().unwrap();
    assert_eq!((c.settled, c.in_flight), (2, 1));
    assert_eq!(c.files_total, 4, "every merged-view file, held once or more");
    assert_eq!(c.extra_bytes, 3000 + 1000, "every settled copy but the largest");
    let rows: Vec<(&str, CopiesKind, bool, u64)> =
        c.rows.iter().map(|r| (r.entry.rel_path.as_str(), r.kind, r.identical, r.extra_bytes)).collect();
    assert_eq!(
        rows,
        vec![
            ("Movies/Twice (2020)/Twice.mkv", CopiesKind::Settled, true, 3000),
            ("Movies/Arriving (2026)/Arriving.mkv", CopiesKind::InFlight, true, 2000),
            ("TV/Show/S01E01.mkv", CopiesKind::Settled, false, 1000),
        ],
        "biggest extra bytes first"
    );
    assert!(c.rows.iter().all(|r| r.served.is_some()), "each says which copy the view serves");
}

#[test]
fn a_copy_from_a_superseded_snapshot_is_shown_and_not_counted() {
    let copy = |region: &str, stale: bool| ViewCopy {
        region: region.into(),
        kind: "file".into(),
        size_bytes: 500,
        mtime_ms: 1,
        content_hash: Some("aa".repeat(32)),
        quality: None,
        stale,
    };
    let entry = |sources: Vec<ViewCopy>| ViewEntry {
        rel_path: "Movies/X/x.mkv".into(),
        kind: "file".into(),
        size_bytes: 500,
        mtime_ms: 1,
        content_hash: Some("aa".repeat(32)),
        quality: None,
        state: ViewState::Admitted,
        copies: sources.len() as u64,
        sources,
    };
    let never = |_: &str| false;
    let stale = copies_row(entry(vec![copy("r1", false), copy("r2", true)]), &never).unwrap();
    assert_eq!((stale.kind, stale.extra_bytes), (CopiesKind::Stale, 500));
    let settled = copies_row(entry(vec![copy("r1", false), copy("r2", false), copy("r3", true)]), &never).unwrap();
    assert_eq!((settled.kind, settled.extra_bytes), (CopiesKind::Settled, 500), "the stale third is not counted");
    assert!(copies_row(entry(vec![copy("r1", false)]), &never).is_none(), "held once is no row");
}
