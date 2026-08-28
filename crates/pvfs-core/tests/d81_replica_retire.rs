//! D81 — the three faults that had to be fixed before multi-root roots.
//!
//! All three were found by testing Chris's "consider all possible cases", and
//! every one of them is a case of the system reporting something it had not
//! done.

use pvfs_core::storage::{host_uri, local_path_of};

const PIN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PIN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// The equivalence three call sites derived separately, in one place.
#[test]
fn a_host_implicit_and_a_pin_qualified_location_name_the_same_file() {
    let path = std::path::Path::new("/share/Data/Media/TV/Show/ep.mkv");
    let bare = format!("file://{}", path.display());
    let mine = host_uri(PIN_A, path).unwrap();

    assert_eq!(local_path_of(&bare, Some(PIN_A)).as_deref(), Some(path));
    assert_eq!(local_path_of(&mine, Some(PIN_A)).as_deref(), Some(path));
    assert_eq!(
        local_path_of(&bare, Some(PIN_A)),
        local_path_of(&mine, Some(PIN_A)),
        "the same bytes on the same disk, however the log spells them"
    );
}

/// ANOTHER box's copy is not ours to stat, and must never be judged gone.
///
/// This is the half that makes the fix safe rather than merely working: the
/// deletion pass decides what to retire, and "I could not resolve it" must
/// never collapse into "it is not there". It used to, via
/// `LocalBackend.stat(&uri).map(..).unwrap_or(false)`.
#[test]
fn another_boxs_location_resolves_to_nothing_here() {
    let path = std::path::Path::new("/share/Data/Media/TV/Show/ep.mkv");
    let theirs = host_uri(PIN_B, path).unwrap();
    assert_eq!(
        local_path_of(&theirs, Some(PIN_A)),
        None,
        "a location pinned to another box is not a local path"
    );
    assert_eq!(
        local_path_of(&theirs, None),
        None,
        "and a box with no pin of its own cannot claim it either"
    );
}

/// A pin is a pin regardless of case.
#[test]
fn pin_comparison_is_case_insensitive() {
    let path = std::path::Path::new("/srv/media/ep.mkv");
    let uri = host_uri(&PIN_A.to_uppercase(), path).unwrap();
    assert_eq!(local_path_of(&uri, Some(PIN_A)).as_deref(), Some(path));
}

// ---------------------------------------------------------------------------
// The behaviour the helper exists for.
// ---------------------------------------------------------------------------

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::Lazy,
    }
}

/// Give this data dir a transport pin, the way `pvfsd --listen` does.
fn give_it_a_pin(data_dir: &std::path::Path, pin: &str) {
    let d = data_dir.join("nettls");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("pin"), pin).unwrap();
}

fn media_forest(dir: &std::path::Path) -> (Engine, String, std::path::PathBuf) {
    let lib = dir.join("lib");
    std::fs::create_dir_all(lib.join("TV").join("Show")).unwrap();
    std::fs::write(lib.join("TV/Show/ep.mkv"), vec![7u8; 2048]).unwrap();

    let (mut engine, _mn) = Engine::init(dir.join("forest").as_path()).unwrap();
    give_it_a_pin(&dir.join("forest"), PIN_A);
    let root = engine.identity.root_node_id.clone();
    let media = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Media".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine.bind_folder(&media, spec(&lib)).unwrap();
    let stats = engine.scan(Some(&media)).unwrap();
    assert_eq!(stats[0].stats.added, 1);
    (engine, media, lib)
}

/// THE BUG: a pin-qualified location for a file that is gone must be retired.
///
/// A replica logs its locations `pvfs-host://<pin>/path` (D75). The deletion
/// pass matched only the bare `file://` prefix, so on a replica it found
/// nothing to consider, skipped the removal behind its `active.is_some()`
/// guard, deleted the `scan_state` row anyway — and reported the removal as
/// done. The stale location then survived every later pass, permanently.
#[test]
fn a_pin_qualified_location_is_retired_when_its_file_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, lib) = media_forest(dir.path());

    let file = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .find(|e| e.node.node_type == pvfs_core::TYPE_FILE)
        .unwrap()
        .node
        .id;

    // Record it the way a REPLICA would, and drop the host-implicit one, so
    // the only location left is the form the deletion pass could not see.
    let path = lib.join("TV/Show/ep.mkv");
    let qualified = host_uri(PIN_A, &path).unwrap();
    engine.add_location(&file, &qualified).unwrap();
    let bare = format!("file://{}", path.display());
    engine.remove_location(&file, &bare).unwrap();
    assert_eq!(engine.locations(&file).unwrap(), vec![qualified.clone()]);

    std::fs::remove_file(&path).unwrap();
    let stats = engine.scan(Some(&media)).unwrap();

    assert_eq!(
        engine.locations(&file).unwrap(),
        Vec::<String>::new(),
        "the file is gone from disk, so its location must be retired whatever \
         form the log spells it in"
    );
    assert_eq!(
        stats[0].stats.removed, 1,
        "and the count must describe what happened"
    );
    engine.close().unwrap();
}

/// The counter must not claim a removal it skipped, and another box's copy
/// must survive.
///
/// `stats.removed` was incremented outside the guard that does the removing,
/// so the pin-qualified case reported `-1 removed` having removed nothing. A
/// counter that lies about the one operation that destroys information is
/// worse than no counter at all.
///
/// HONEST LIMIT, found by reverting the fix and watching this test pass anyway:
/// a foreign pin matches neither prefix, so `theirs` is never even considered
/// by the deletion pass — this holds for that reason, not because the
/// resolve-before-stat guard caught it. That guard is defensive and currently
/// unreachable from here. The property it protects is tested directly, on the
/// helper, by `another_boxs_location_resolves_to_nothing_here`.
#[test]
fn a_location_belonging_to_another_box_is_left_alone_and_not_counted() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, lib) = media_forest(dir.path());

    let file = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .find(|e| e.node.node_type == pvfs_core::TYPE_FILE)
        .unwrap()
        .node
        .id;

    // Another holder also has these bytes, at the same path on ITS disk.
    let path = lib.join("TV/Show/ep.mkv");
    let theirs = host_uri(PIN_B, &path).unwrap();
    engine.add_location(&file, &theirs).unwrap();

    std::fs::remove_file(&path).unwrap();
    let stats = engine.scan(Some(&media)).unwrap();

    let left = engine.locations(&file).unwrap();
    assert!(
        left.contains(&theirs),
        "this box cannot see another box's disk and must not declare its copy \
         gone: {left:?}"
    );
    assert_eq!(
        stats[0].stats.removed, 1,
        "exactly one location was ours to retire"
    );
    engine.close().unwrap();
}

/// A change is counted ONCE, not on every pass for as long as it is pending.
///
/// Pending changes wait for an operator by design (doc 04 §4.4), and
/// `scan_state` is deliberately not advanced. But re-counting the same change
/// every pass kept `stats.changed` permanently non-zero, which fires the
/// watcher's progress signal forever and silences the stall detector — a
/// wedged job reporting `running`, which is the exact failure D78 exists to
/// prevent.
#[test]
fn an_unresolved_change_is_counted_once_not_every_pass() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, lib) = media_forest(dir.path());

    std::fs::write(lib.join("TV/Show/ep.mkv"), vec![9u8; 4096]).unwrap();

    let first = engine.scan(Some(&media)).unwrap();
    assert_eq!(first[0].stats.changed, 1, "detected on the pass that finds it");

    let second = engine.scan(Some(&media)).unwrap();
    assert_eq!(
        second[0].stats.changed, 0,
        "still pending, still unresolved — but NOT news a second time"
    );
    let third = engine.scan(Some(&media)).unwrap();
    assert_eq!(third[0].stats.changed, 0, "nor a third");
    engine.close().unwrap();
}

/// The add-side twin: a pin-qualified location already there is NOT missing.
///
/// Found on the lab holder, not in a test: every watch pass wrote **1,998
/// FileLocationAdded events** for files whose locations were already recorded —
/// because the "is this location live?" check compared only the bare `file://`
/// form, and a replica records pin-qualified. Each one is a round trip to the
/// owner, which is why a pass over 2,000 files never finished, which is why the
/// job looked stalled, which is what sent me looking in the first place.
///
/// The same missing equivalence as the retire bug, on the opposite path, doing
/// the opposite damage: one silently dropped work it should have done, the
/// other endlessly repeated work already done.
#[test]
fn a_pin_qualified_location_is_not_rediscovered_every_pass() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, lib) = media_forest(dir.path());

    let file = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .find(|e| e.node.node_type == pvfs_core::TYPE_FILE)
        .unwrap()
        .node
        .id;

    // Record it the way a replica does, and drop the host-implicit form.
    let path = lib.join("TV/Show/ep.mkv");
    let qualified = host_uri(PIN_A, &path).unwrap();
    engine.add_location(&file, &qualified).unwrap();
    engine
        .remove_location(&file, &format!("file://{}", path.display()))
        .unwrap();

    let again = engine.scan(Some(&media)).unwrap();
    assert_eq!(
        again[0].stats.added, 0,
        "the bytes are already recorded as living here — a differently spelled \
         URI for the same path on the same disk is not a discovery"
    );
    assert_eq!(again[0].stats.unchanged, 1);
    // D85 — follow the successor. A scan now fills any empty content hash it
    // meets, and filling one mints a new node that the location moves onto. The
    // property this test guards is unchanged and still asserted above: `added`
    // is 0 and the pass counts the file `unchanged`, so a differently spelled
    // URI for the same path is still not a discovery. What must also hold is
    // that exactly ONE location survives the move — not two.
    let now = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .find(|e| e.node.node_type == pvfs_core::TYPE_FILE)
        .unwrap()
        .node
        .id;
    assert_eq!(
        engine.locations(&now).unwrap(),
        vec![qualified],
        "and nothing was added alongside it"
    );
    engine.close().unwrap();
}
