//! D154 — a catalogue pass keeps what it did.
//!
//! `scan_region_catalogue` hashed every file first and committed every row in
//! one transaction at the end, so a stop during the hashing committed nothing.
//! On mediabox a region's first pass takes hours, and every daemon restart
//! threw one away whole: two regions went from their creation with no rows at
//! all. Rows now commit in batches as the pass goes; the stale-row sweep and
//! the head stay with a COMPLETE pass.
//!
//! A real stop races the pass it stops, so these tests interrupt a pass at a
//! chosen file with `Engine::interrupt_catalogue_at`: a stop raises the same
//! flag SIGTERM does, and a kill ends the pass the way SIGKILL leaves it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

/// A forest at `data` whose `Library` is a catalogue region bound to `lib`,
/// with a stop flag of its own (lowered).
fn catalogue_forest(data: &std::path::Path, lib: &std::path::Path) -> (Engine, String, Arc<AtomicBool>) {
    let (mut e, _mn) = Engine::init(data).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = folder(&mut e, &root, "Library");
    e.region_mark_as(&region, "catalogue", None).unwrap();
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
    let stop = Arc::new(AtomicBool::new(false));
    e.set_cancel(Arc::clone(&stop));
    (e, region, stop)
}

/// `e0.mkv` … `e{n-1}.mkv`, flat, each a different size. The walk lists a
/// directory in name order, so this is the order the pass takes them in.
fn flat_library(dir: &std::path::Path, name: &str, n: usize) -> std::path::PathBuf {
    let lib = dir.join(name);
    std::fs::create_dir_all(&lib).unwrap();
    for i in 0..n {
        std::fs::write(lib.join(format!("e{i}.mkv")), vec![i as u8; 100 + i]).unwrap();
    }
    lib
}

fn file_rows(e: &Engine, region: &str) -> Vec<String> {
    e.region_entries(&region.to_string())
        .unwrap()
        .into_iter()
        .filter(|r| r.kind == "file")
        .map(|r| r.rel_path)
        .collect()
}

fn entry(e: &Engine, region: &str, rel: &str) -> RegionEntry {
    e.region_entries(&region.to_string())
        .unwrap()
        .into_iter()
        .find(|r| r.rel_path == rel)
        .unwrap_or_else(|| panic!("no row for {rel}"))
}

fn heads(e: &Engine, region: &str) -> Vec<u64> {
    e.region_snapshots(&region.to_string())
        .unwrap()
        .into_iter()
        .map(|s| s.seq)
        .collect()
}

fn names(n: std::ops::Range<usize>) -> Vec<String> {
    n.map(|i| format!("e{i}.mkv")).collect()
}

/// The mediabox case: a first pass stopped part-way keeps the rows it made,
/// and publishes no head for them.
#[test]
fn a_stopped_first_pass_keeps_its_rows_and_publishes_no_head() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 6);
    std::fs::create_dir_all(lib.join("Extras")).unwrap();
    let (mut e, region, _stop) = catalogue_forest(&dir.path().join("forest"), &lib);
    let tip = e.log_tip().unwrap();

    // The stop arrives as the fourth file is taken in hand. It has no row and
    // no sidecar, so it must be read, and the stop lands inside that read.
    e.interrupt_catalogue_at(3, false);
    let st = e.scan_routed(Some(&region), None, 0).unwrap().remove(0).stats;
    assert!(st.cancelled, "the pass says it stopped");
    assert_eq!(st.added, 3, "the three files before the stop; the fourth was abandoned mid-read");
    assert_eq!(
        file_rows(&e, &region),
        names(0..3),
        "committed although no batch (1,000 rows, 30 s) had closed: a stop commits what it holds"
    );
    assert_eq!(entry(&e, &region, "Extras").kind, "dir", "and the directory rows with them");
    assert!(heads(&e, &region).is_empty(), "no head for a partial pass");
    assert_eq!(e.log_tip().unwrap(), tip, "so the log hears nothing");
}

/// … and the next pass carries on from there: the kept files are known by
/// their rows, the rest are read, and ONE head names every row.
#[test]
fn the_next_pass_resumes_and_publishes_every_row_once() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 6);
    std::fs::create_dir_all(lib.join("Extras")).unwrap();
    let forest = dir.path().join("forest");
    let (mut e, region, stop) = catalogue_forest(&forest, &lib);
    let tip = e.log_tip().unwrap();
    e.interrupt_catalogue_at(3, false);
    e.scan_routed(Some(&region), None, 0).unwrap();

    stop.store(false, Ordering::SeqCst);
    let st = e.scan_routed(Some(&region), None, 0).unwrap().remove(0).stats;
    assert!(!st.cancelled);
    assert_eq!(
        (st.added, st.unchanged, st.changed, st.removed),
        (3, 3, 0, 0),
        "the kept rows vouch for their files: unchanged, not read again"
    );
    assert_eq!(file_rows(&e, &region), names(0..6));
    assert_eq!(heads(&e, &region), vec![1], "one head for the pass, not one per batch");
    assert_eq!(e.log_tip().unwrap(), tip + 1);
    let snap = &e.region_snapshots(&region).unwrap()[0];
    assert_eq!(snap.entries, 7, "six files and Extras");

    // The published manifest is exactly the rows, as a single-shot pass
    // would have written it.
    let rows = e.region_entries(&region).unwrap();
    let want = Engine::region_manifest_bytes(&region, 1, &rows);
    let got = std::fs::read(forest.join("regions").join(&region).join("manifest.1")).unwrap();
    assert_eq!(got, want);
    assert_eq!(blake3::hash(&got).to_hex().to_string(), snap.manifest_hash);
}

/// A stopped pass on a region already published: the row it changed is kept,
/// but the head stays the last complete pass's, and nothing is swept. The
/// file it never reached is "not seen", not "gone".
#[test]
fn a_stopped_pass_sweeps_nothing_and_leaves_the_head() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 6);
    let (mut e, region, stop) = catalogue_forest(&dir.path().join("forest"), &lib);
    e.scan_routed(Some(&region), None, 0).unwrap();
    assert_eq!(heads(&e, &region), vec![1]);

    let recut = b"a new cut, longer than the old one";
    std::fs::write(lib.join("e0.mkv"), recut).unwrap();
    std::fs::remove_file(lib.join("e5.mkv")).unwrap();
    let tip = e.log_tip().unwrap();

    // Raised as e2 is taken in hand. e2's row vouches for it, so there is no
    // read to abandon; the stop lands before e3.
    e.interrupt_catalogue_at(2, false);
    let st = e.scan_routed(Some(&region), None, 0).unwrap().remove(0).stats;
    assert!(st.cancelled);
    assert_eq!((st.changed, st.unchanged, st.removed), (1, 2, 0), "a stopped pass sweeps nothing");
    assert_eq!(entry(&e, &region, "e0.mkv").size_bytes, recut.len() as u64, "the changed row is committed");
    assert!(
        file_rows(&e, &region).contains(&"e5.mkv".to_string()),
        "the deleted file's row waits for a complete pass"
    );
    assert_eq!(heads(&e, &region), vec![1], "the head is still the last complete pass's");
    assert_eq!(e.log_tip().unwrap(), tip);

    stop.store(false, Ordering::SeqCst);
    let st = e.scan_routed(Some(&region), None, 0).unwrap().remove(0).stats;
    assert!(!st.cancelled);
    assert_eq!((st.changed, st.removed), (0, 1), "e0 is already current; e5 is swept now");
    assert_eq!(file_rows(&e, &region), names(0..5));
    assert_eq!(heads(&e, &region), vec![1, 2]);
    assert_eq!(e.log_tip().unwrap(), tip + 1);
}

/// A kill (SIGKILL after the stop timeout, a crash, a power cut) loses only
/// the batch the pass was holding. Every batch before it is kept.
#[test]
fn a_killed_pass_keeps_every_whole_batch() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 6);
    let (mut e, region, _stop) = catalogue_forest(&dir.path().join("forest"), &lib);
    e.set_catalogue_batch(2, u64::MAX);

    e.interrupt_catalogue_at(5, true);
    assert!(e.scan_routed(Some(&region), None, 0).is_err(), "a killed pass is not a clean one");
    assert_eq!(
        file_rows(&e, &region),
        names(0..4),
        "two whole batches; e4, hashed but still held, died with the pass"
    );
    assert!(heads(&e, &region).is_empty());

    let st = e.scan_routed(Some(&region), None, 0).unwrap().remove(0).stats;
    assert_eq!((st.added, st.unchanged), (2, 4));
    assert_eq!(heads(&e, &region), vec![1]);
    assert_eq!(e.region_snapshots(&region).unwrap()[0].entries, 6);
}

/// The clock closes a batch too. While hashing, 1,000 rows can take hours to
/// fill (one film is minutes of reading), so the time bound is what limits a
/// kill's loss there.
#[test]
fn the_clock_closes_a_batch_too() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 6);
    let (mut e, region, _stop) = catalogue_forest(&dir.path().join("forest"), &lib);
    // No row count will close a batch; every file finds the clock past due.
    e.set_catalogue_batch(usize::MAX, 0);

    e.interrupt_catalogue_at(3, true);
    assert!(e.scan_routed(Some(&region), None, 0).is_err());
    assert_eq!(file_rows(&e, &region), names(0..3), "each file was committed on its own");
}

/// A stop raised once the last file is done still ends the pass as stopped:
/// no sweep and no head. The watch meets this whenever its files are inside
/// the settle window, which leaves the pass nothing to hash.
#[test]
fn a_stop_after_the_last_file_still_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let lib = flat_library(dir.path(), "lib", 3);
    let (mut e, region, stop) = catalogue_forest(&dir.path().join("forest"), &lib);
    e.scan_routed(Some(&region), None, 0).unwrap();
    std::fs::remove_file(lib.join("e2.mkv")).unwrap();

    stop.store(true, Ordering::SeqCst);
    // An hour's settle window: every file is "still being written", so the
    // pass has none to take.
    let st = e.scan_routed(Some(&region), None, 3_600_000).unwrap().remove(0).stats;
    assert!(st.cancelled);
    assert_eq!(st.removed, 0);
    assert_eq!(file_rows(&e, &region), names(0..3));
    assert_eq!(heads(&e, &region), vec![1]);
}

/// Batches change WHEN rows are committed, not what a complete pass
/// publishes: one head per pass, holding the same rows a single-transaction
/// pass writes.
#[test]
fn small_batches_publish_one_head_with_the_same_rows() {
    let dir = tempfile::tempdir().unwrap();
    let lib_a = flat_library(dir.path(), "lib-a", 6);
    let lib_b = flat_library(dir.path(), "lib-b", 6);
    for lib in [&lib_a, &lib_b] {
        std::fs::create_dir_all(lib.join("Season 01")).unwrap();
        std::fs::write(lib.join("Season 01").join("s01e01.mkv"), b"pilot").unwrap();
        std::fs::create_dir_all(lib.join("Extras")).unwrap();
    }
    let (mut a, ra, _sa) = catalogue_forest(&dir.path().join("forest-a"), &lib_a);
    let (mut b, rb, _sb) = catalogue_forest(&dir.path().join("forest-b"), &lib_b);
    a.set_catalogue_batch(1, u64::MAX);

    let tip = a.log_tip().unwrap();
    let st = a.scan_routed(Some(&ra), None, 0).unwrap().remove(0).stats;
    b.scan_routed(Some(&rb), None, 0).unwrap();
    assert_eq!(st.added, 7);
    assert_eq!(heads(&a, &ra), vec![1], "nine batches, one head");
    assert_eq!(a.log_tip().unwrap(), tip + 1);

    // Paths, kinds, sizes and hashes; the mtimes differ because the two
    // libraries were written a moment apart.
    let strip = |rows: Vec<RegionEntry>| {
        rows.into_iter()
            .map(|r| (r.rel_path, r.kind, r.size_bytes, r.content_hash))
            .collect::<Vec<_>>()
    };
    assert_eq!(strip(a.region_entries(&ra).unwrap()), strip(b.region_entries(&rb).unwrap()));
}
