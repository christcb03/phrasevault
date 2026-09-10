//! D125 items 2–3 — a catalogue region's binding catalogues instead of
//! ingesting: rows in `region_entries`, not one event in the log.
//!
//! Until item 6 lands `region mark --catalogue`, a region is flipped the way
//! the spike does it — straight into `regions.kind`, with no generation file
//! and no state_root, which is the row shape item 6 will produce.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

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

fn flip_to_catalogue(data: &std::path::Path, region: &str) {
    let c = rusqlite::Connection::open(data.join("index.db")).unwrap();
    c.execute(
        "UPDATE regions SET kind='catalogue', log_file=NULL, state_root=NULL WHERE node_id=?1",
        [region],
    )
    .unwrap();
}

fn bind(e: &mut Engine, region: &str, lib: &std::path::Path, policy: HashPolicy) {
    e.bind_folder(
        &region.to_string(),
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: policy,
        },
    )
    .expect("binding a catalogue region at its root is the normal case");
}

/// A forest at `data` whose `Library` is a catalogue region bound to `lib`.
fn catalogue_forest(data: &std::path::Path, lib: &std::path::Path, policy: HashPolicy) -> (Engine, String) {
    let (mut e, _mn) = Engine::init(data).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = folder(&mut e, &root, "Library");
    e.region_mark(&region).unwrap();
    e.close().unwrap();
    flip_to_catalogue(data, &region);
    let mut e = Engine::open(data).unwrap();
    bind(&mut e, &region, lib, policy);
    (e, region)
}

/// `lib/a.mkv`, `lib/sub/b.mkv`, and `lib/empty/` — the empty directory is
/// the point.
fn library(dir: &std::path::Path) -> std::path::PathBuf {
    let lib = dir.join("lib");
    std::fs::create_dir_all(lib.join("sub")).unwrap();
    std::fs::create_dir_all(lib.join("empty")).unwrap();
    std::fs::write(lib.join("a.mkv"), b"aaa").unwrap();
    std::fs::write(lib.join("sub").join("b.mkv"), b"bbbbb").unwrap();
    lib
}

fn paths(e: &Engine, region: &str) -> Vec<(String, String)> {
    e.region_entries(&region.to_string())
        .unwrap()
        .into_iter()
        .map(|r| (r.rel_path, r.kind))
        .collect()
}

fn entry(e: &Engine, region: &str, rel: &str) -> pvfs_core::RegionEntry {
    e.region_entries(&region.to_string())
        .unwrap()
        .into_iter()
        .find(|r| r.rel_path == rel)
        .unwrap_or_else(|| panic!("no row for {rel}"))
}

fn s(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
}

/// Item 2 — the scan of a catalogue region writes rows and appends nothing.
#[test]
fn a_catalogue_binding_writes_rows_and_not_one_event() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    let (mut e, region) = catalogue_forest(&dir.path().join("forest"), &lib, HashPolicy::OnAdd);

    let tip = e.log_tip().unwrap();
    let reports = e.scan_routed(Some(&region), None, 0).unwrap();
    assert_eq!(e.log_tip().unwrap(), tip + 1, "a catalogue scan tells the log ONE thing: its head (item 4)");
    assert!(e.children(&region).unwrap().is_empty(), "and mints no nodes under the region");
    assert_eq!(
        paths(&e, &region),
        s(&[("a.mkv", "file"), ("empty", "dir"), ("sub", "dir"), ("sub/b.mkv", "file")]),
        "one row per file and per directory, in manifest (bytewise path) order"
    );
    let st = &reports[0].stats;
    assert_eq!((st.added, st.changed, st.unchanged, st.removed), (2, 0, 0, 0));
    assert_eq!(st.empty_dirs, 1);

    // A second pass changes nothing and says so.
    let st = e.scan_routed(Some(&region), None, 0).unwrap().remove(0).stats;
    assert_eq!((st.added, st.changed, st.unchanged, st.removed), (0, 0, 2, 0));
    assert_eq!(e.log_tip().unwrap(), tip + 1, "and an unchanged catalogue publishes nothing");
}

/// Item 3 — an empty folder on disk is an empty folder in the catalogue, and
/// stops being one when it is removed. Named for Chris: "if any of the
/// trees/regions have an empty folder that empty folder needs to be presented
/// as an empty folder".
#[test]
fn an_empty_folder_is_presented_as_an_empty_folder() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    let (mut e, region) = catalogue_forest(&dir.path().join("forest"), &lib, HashPolicy::OnAdd);
    e.scan_routed(Some(&region), None, 0).unwrap();
    let row = entry(&e, &region, "empty");
    assert_eq!((row.kind.as_str(), row.size_bytes, row.content_hash), ("dir", 0, None));

    std::fs::remove_dir(lib.join("empty")).unwrap();
    let st = e.scan_routed(Some(&region), None, 0).unwrap().remove(0).stats;
    assert_eq!(st.removed, 1);
    assert_eq!(paths(&e, &region), s(&[("a.mkv", "file"), ("sub", "dir"), ("sub/b.mkv", "file")]));
}

/// Item 3 — a row whose file is gone is deleted; the rest are untouched.
#[test]
fn a_row_whose_file_is_gone_is_deleted_and_the_rest_stay() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    let (mut e, region) = catalogue_forest(&dir.path().join("forest"), &lib, HashPolicy::OnAdd);
    e.scan_routed(Some(&region), None, 0).unwrap();
    let before = entry(&e, &region, "sub/b.mkv");

    std::fs::remove_file(lib.join("a.mkv")).unwrap();
    let st = e.scan_routed(Some(&region), None, 0).unwrap().remove(0).stats;
    assert_eq!((st.removed, st.unchanged), (1, 1));
    assert_eq!(paths(&e, &region), s(&[("empty", "dir"), ("sub", "dir"), ("sub/b.mkv", "file")]));
    let after = entry(&e, &region, "sub/b.mkv");
    assert_eq!(after.content_hash, before.content_hash, "an untouched file keeps its hash without a re-read");
}

/// Item 3 — the hash comes from the sidecar when there is one (D103), under
/// EITHER policy; only a missing sidecar is where the policy decides.
#[test]
fn the_hash_comes_from_the_sidecar_and_not_from_the_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    // Forest A hashes on_add and leaves sidecars beside both files.
    let (mut a, ra) = catalogue_forest(&dir.path().join("fa"), &lib, HashPolicy::OnAdd);
    a.scan_routed(Some(&ra), None, 0).unwrap();
    let real_a = entry(&a, &ra, "a.mkv").content_hash.expect("on_add hashes");
    let real_b = entry(&a, &ra, "sub/b.mkv").content_hash.expect("on_add hashes");
    a.close().unwrap();

    // Plant a sentinel the bytes could not produce (the D103 technique).
    let sidecar = pvfs_core::sync::manifest_sidecar_path(&lib.join("a.mkv"));
    let sentinel = "5e0771e1".repeat(8);
    let text = std::fs::read_to_string(&sidecar).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    assert_eq!(lines[2], real_a, "line 3 is the whole-file hash");
    lines[2] = sentinel.clone();
    std::fs::write(&sidecar, lines.join("\n") + "\n").unwrap();
    // And one file with no sidecar at all.
    std::fs::write(lib.join("c.mkv"), b"cc").unwrap();

    // Forest B, on_add: sentinel for a (sidecar), real for b (sidecar), a
    // fresh hash for c (bytes).
    let (mut b, rb) = catalogue_forest(&dir.path().join("fb"), &lib, HashPolicy::OnAdd);
    b.scan_routed(Some(&rb), None, 0).unwrap();
    assert_eq!(entry(&b, &rb, "a.mkv").content_hash.as_deref(), Some(sentinel.as_str()));
    assert_eq!(entry(&b, &rb, "sub/b.mkv").content_hash.as_deref(), Some(real_b.as_str()));
    let c_hash = entry(&b, &rb, "c.mkv").content_hash.expect("on_add hashes a file with no sidecar");
    assert_ne!(c_hash, sentinel);
    b.close().unwrap();

    // Forest C, never: the sidecars are still free, the missing one stays NULL.
    std::fs::remove_file(pvfs_core::sync::manifest_sidecar_path(&lib.join("c.mkv"))).ok();
    let (mut c, rc) = catalogue_forest(&dir.path().join("fc"), &lib, HashPolicy::Never);
    c.scan_routed(Some(&rc), None, 0).unwrap();
    assert_eq!(entry(&c, &rc, "a.mkv").content_hash.as_deref(), Some(sentinel.as_str()));
    assert_eq!(entry(&c, &rc, "c.mkv").content_hash, None, "never means never reads the bytes");
}

/// Item 3 — the settle window (D112) applies: a file still being written gets
/// no NEW row this pass, and keeps its last settled one, because "still
/// copying" is not "gone".
#[test]
fn a_settling_file_keeps_its_last_settled_row() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    let (mut e, region) = catalogue_forest(&dir.path().join("forest"), &lib, HashPolicy::OnAdd);
    e.scan_routed(Some(&region), None, 0).unwrap();
    let settled = entry(&e, &region, "a.mkv");
    assert_eq!(settled.size_bytes, 3);

    std::fs::write(lib.join("a.mkv"), b"aaaaaaaaaa").unwrap(); // fresh mtime AND ctime
    let st = e
        .scan_routed(Some(&region), None, pvfs_core::WATCH_SETTLE_MS)
        .unwrap()
        .remove(0)
        .stats;
    assert_eq!(st.settling, 2, "both files are younger than the window; a.mkv is the one under test");
    assert_eq!(st.removed, 0, "a settling file's row is not a stale row");
    assert_eq!(paths(&e, &region).len(), 4, "unseen is not gone");
    assert_eq!(entry(&e, &region, "a.mkv"), settled, "the last settled row stands");

    let st = e.scan_routed(Some(&region), None, 0).unwrap().remove(0).stats;
    assert_eq!(st.changed, 1);
    let now = entry(&e, &region, "a.mkv");
    assert_eq!(now.size_bytes, 10);
    assert_ne!(now.content_hash, settled.content_hash, "a changed file is re-hashed, not carried");
}

/// Item 2 — a binding INSIDE a catalogue region is refused at bind time, with
/// the reason, rather than per file at the append gate.
#[test]
fn a_binding_inside_a_catalogue_region_is_refused_at_bind_time() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    let data = dir.path().join("forest");
    let (mut e, _mn) = Engine::init(&data).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = folder(&mut e, &root, "Library");
    let inner = folder(&mut e, &region, "Sub"); // exists before the mark
    e.region_mark(&region).unwrap();
    e.close().unwrap();
    flip_to_catalogue(&data, &region);
    let mut e = Engine::open(&data).unwrap();

    let err = e
        .bind_folder(
            &inner,
            BindSpec {
                source_uri: format!("file://{}", lib.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .expect_err("a folder inside a catalogue region cannot be bound");
    assert!(err.to_string().contains("catalogue region"), "says why: {err}");
    // The region's own root still binds (the normal case).
    bind(&mut e, &region, &lib, HashPolicy::OnAdd);
}
