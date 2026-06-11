//! P1 test plan — doc 04 §10.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use pvfs_core::{
    BindSpec, Engine, HashPolicy, NodeSpec, PvfsError, ResolveAction, VerifyOutcome, TYPE_FOLDER,
};

fn new_forest() -> (tempfile::TempDir, Engine, pvfs_core::Mnemonic) {
    let dir = tempfile::tempdir().unwrap();
    let (engine, m) = Engine::init(dir.path()).unwrap();
    (dir, engine, m)
}

fn write_file(path: &Path, contents: &[u8]) {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).unwrap();
    }
    fs::File::create(path).unwrap().write_all(contents).unwrap();
}

fn bind_spec(dir: &Path, policy: HashPolicy) -> BindSpec {
    BindSpec {
        source_uri: pvfs_core::storage::path_to_uri(&fs::canonicalize(dir).unwrap()).unwrap(),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: policy,
    }
}

/// Build a forest with a bound folder over a fixture dir. Returns
/// (data_tempdir, fixture_tempdir, engine, bound folder id).
fn bound_fixture(policy: HashPolicy) -> (tempfile::TempDir, tempfile::TempDir, Engine, String) {
    let (data, mut engine, _m) = new_forest();
    let fixture = tempfile::tempdir().unwrap();
    write_file(&fixture.path().join("movies/alpha.mkv"), b"alpha-bytes");
    write_file(&fixture.path().join("movies/beta.mp4"), b"beta-bytes!");
    write_file(&fixture.path().join("notes.txt"), b"hello notes");
    let root = engine.identity.root_node_id.clone();
    let folder = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "library".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine
        .bind_folder(&folder, bind_spec(fixture.path(), policy))
        .unwrap();
    (data, fixture, engine, folder)
}

fn find_by_label(engine: &Engine, parent: &str, label: &str) -> Option<String> {
    engine
        .children(&parent.to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.node.label == label)
        .map(|c| c.node.id)
}

// §10.2/§10.3 — scan indexes a tree of pointers; rescan is a no-op
#[test]
fn scan_mirrors_directory_and_is_idempotent() {
    let (_data, _fixture, mut engine, folder) = bound_fixture(HashPolicy::Lazy);
    let reports = engine.scan(Some(&folder)).unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].stats.added, 3);
    assert_eq!(reports[0].stats.changed, 0);

    let movies = find_by_label(&engine, &folder, "movies").expect("movies subfolder");
    let alpha = find_by_label(&engine, &movies, "alpha.mkv").expect("alpha indexed");
    let locs = engine.locations(&alpha).unwrap();
    assert_eq!(locs.len(), 1, "pointer location recorded");
    assert!(locs[0].starts_with("file://"));

    // rescan: everything unchanged
    let again = engine.scan(Some(&folder)).unwrap();
    assert_eq!(again[0].stats.added, 0);
    assert_eq!(again[0].stats.unchanged, 3);
}

// extension filter + skipped count
#[test]
fn extension_filter() {
    let (_data, mut engine, _m) = {
        let (d, e, m) = new_forest();
        (d, e, m)
    };
    let fixture = tempfile::tempdir().unwrap();
    write_file(&fixture.path().join("a.mkv"), b"a");
    write_file(&fixture.path().join("b.txt"), b"b");
    let root = engine.identity.root_node_id.clone();
    let folder = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "vids".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    let mut spec = bind_spec(fixture.path(), HashPolicy::Lazy);
    spec.extensions = "mkv".into();
    engine.bind_folder(&folder, spec).unwrap();
    let r = engine.scan(Some(&folder)).unwrap();
    assert_eq!(r[0].stats.added, 1);
    assert_eq!(r[0].stats.skipped, 1);
    assert!(find_by_label(&engine, &folder, "b.txt").is_none());
}

// §10.4 — disk deletion soft-removes; restore re-attaches the same node
#[test]
fn disk_delete_and_restore() {
    let (_data, fixture, mut engine, folder) = bound_fixture(HashPolicy::Lazy);
    engine.scan(Some(&folder)).unwrap();
    let notes = find_by_label(&engine, &folder, "notes.txt").unwrap();

    fs::remove_file(fixture.path().join("notes.txt")).unwrap();
    let r = engine.scan(Some(&folder)).unwrap();
    assert_eq!(r[0].stats.removed, 1);
    assert!(engine.locations(&notes).unwrap().is_empty());
    let st = engine.stat_node(&notes).unwrap();
    assert!(st.unavailable, "no readable location ⇒ unavailable");
    assert!(
        engine.get_node(&notes).unwrap().is_some(),
        "node + metadata kept (soft)"
    );

    // restore identical bytes ⇒ same node gets its location back
    write_file(&fixture.path().join("notes.txt"), b"hello notes");
    let r = engine.scan(Some(&folder)).unwrap();
    assert_eq!(r[0].stats.added, 1);
    assert_eq!(engine.locations(&notes).unwrap().len(), 1);
    assert!(!engine.stat_node(&notes).unwrap().unavailable);
}

// §10.5 — changed file: flag, refuse to serve, operator resolve
#[test]
fn changed_file_flag_and_resolve() {
    let (_data, fixture, mut engine, folder) = bound_fixture(HashPolicy::OnAdd);
    engine.scan(Some(&folder)).unwrap();
    let movies = find_by_label(&engine, &folder, "movies").unwrap();
    let alpha = find_by_label(&engine, &movies, "alpha.mkv").unwrap();

    // change contents (size differs)
    write_file(
        &fixture.path().join("movies/alpha.mkv"),
        b"alpha-bytes-NEW-LONGER",
    );
    let r = engine.scan(Some(&folder)).unwrap();
    assert_eq!(r[0].stats.changed, 1);

    let changes = engine.changes().unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].file_id, alpha);

    // flagged ⇒ refuse to serve from that location
    let mut sink = Vec::new();
    assert!(matches!(
        engine.cat(&alpha, None, &mut sink),
        Err(PvfsError::NotFound { .. })
    ));

    // resolve --replace: successor node carries the new bytes
    let new_id = engine.resolve(&alpha, ResolveAction::Replace).unwrap();
    assert_ne!(new_id, alpha);
    assert!(engine.changes().unwrap().is_empty());
    let mut out = Vec::new();
    engine.cat(&new_id, None, &mut out).unwrap();
    assert_eq!(out, b"alpha-bytes-NEW-LONGER");
    // old node is an orphan kept for review
    let orphans: Vec<String> = engine
        .list_orphans()
        .unwrap()
        .into_iter()
        .map(|n| n.id)
        .collect();
    assert!(orphans.contains(&alpha));
    // successor sits where the old node lived
    assert_eq!(
        find_by_label(&engine, &movies, "alpha.mkv").unwrap(),
        new_id
    );
}

#[test]
fn changed_file_resolve_delete_purge() {
    let (_data, fixture, mut engine, folder) = bound_fixture(HashPolicy::Lazy);
    engine.scan(Some(&folder)).unwrap();
    let beta = {
        let movies = find_by_label(&engine, &folder, "movies").unwrap();
        find_by_label(&engine, &movies, "beta.mp4").unwrap()
    };
    write_file(&fixture.path().join("movies/beta.mp4"), b"tampered-content!!");
    engine.scan(Some(&folder)).unwrap();
    engine
        .resolve(&beta, ResolveAction::Delete { purge: true })
        .unwrap();
    assert!(engine.get_node(&beta).unwrap().is_none(), "purged");
    assert!(
        fixture.path().join("movies/beta.mp4").exists(),
        "on-disk file never touched"
    );
}

// §10.6 — read path verification + quarantine + loc verify repair
#[test]
fn integrity_quarantine_and_repair() {
    let (_data, fixture, mut engine, folder) = bound_fixture(HashPolicy::OnAdd);
    engine.scan(Some(&folder)).unwrap();
    let movies = find_by_label(&engine, &folder, "movies").unwrap();
    let alpha = find_by_label(&engine, &movies, "alpha.mkv").unwrap();
    let path = fixture.path().join("movies/alpha.mkv");

    // good read first
    let mut out = Vec::new();
    engine.cat(&alpha, None, &mut out).unwrap();
    assert_eq!(out, b"alpha-bytes");

    // corrupt SAME length + restore mtime ⇒ scan can't see it, hash check can
    let orig_mtime = fs::metadata(&path).unwrap().modified().unwrap();
    write_file(&path, b"alpha-bytEs"); // same length
    let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_times(fs::FileTimes::new().set_modified(orig_mtime)).unwrap();

    let r = engine.scan(Some(&folder)).unwrap();
    assert_eq!(r[0].stats.changed, 0, "size+mtime unchanged: scan is blind");

    let mut out = Vec::new();
    match engine.cat(&alpha, None, &mut out) {
        Err(PvfsError::Integrity { .. }) => {}
        other => panic!("expected Integrity, got {other:?}"),
    }
    // quarantined now ⇒ unavailable, next cat refuses fast
    assert!(engine.stat_node(&alpha).unwrap().unavailable);
    let mut out = Vec::new();
    assert!(matches!(
        engine.cat(&alpha, None, &mut out),
        Err(PvfsError::NotFound { .. })
    ));

    // repair the bytes, verify lifts quarantine
    write_file(&path, b"alpha-bytes");
    let results = engine.loc_verify(&alpha).unwrap();
    assert!(results.iter().all(|(_, o)| *o == VerifyOutcome::Ok));
    let mut out = Vec::new();
    engine.cat(&alpha, None, &mut out).unwrap();
    assert_eq!(out, b"alpha-bytes");
}

// §10.7 — lazy hashing: fill via successor node
#[test]
fn lazy_hash_fill() {
    let (_data, _fixture, mut engine, folder) = bound_fixture(HashPolicy::Lazy);
    engine.scan(Some(&folder)).unwrap();
    let notes = find_by_label(&engine, &folder, "notes.txt").unwrap();

    // lazy: serves without verification
    let mut out = Vec::new();
    engine.cat(&notes, None, &mut out).unwrap();

    let hashed = engine.hash_node(&notes).unwrap();
    assert_ne!(hashed, notes, "hash fill re-identifies (successor node)");
    // idempotent on the successor
    assert_eq!(engine.hash_node(&hashed).unwrap(), hashed);
    // locations moved; verified read works on successor
    assert_eq!(engine.locations(&hashed).unwrap().len(), 1);
    let mut out = Vec::new();
    engine.cat(&hashed, None, &mut out).unwrap();
    assert_eq!(out, b"hello notes");
    // and range reads work (unverified)
    let mut out = Vec::new();
    engine
        .cat(
            &hashed,
            Some(pvfs_core::ByteRange { start: 6, end: Some(11) }),
            &mut out,
        )
        .unwrap();
    assert_eq!(out, b"notes");
}

// §10.9 — temp spool sweep
#[test]
fn temp_spool_sweep() {
    let (data, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let t = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: pvfs_core::TYPE_FILE.into(),
                label: "preview.bin".into(),
                payload: pvfs_core::FilePayload::default().encode(),
                is_temp: true,
                creation_nonce: None,
            },
        )
        .unwrap();
    let mut src: &[u8] = b"managed-temp-bytes";
    engine.write_managed_temp(&t, &mut src).unwrap();
    let spool_file = data.path().join("tmp").join(&t);
    assert!(spool_file.exists());
    let mut out = Vec::new();
    engine.cat(&t, None, &mut out).unwrap();
    assert_eq!(out, b"managed-temp-bytes");

    // stale spool file gets swept at next open
    write_file(&data.path().join("tmp/deadbeef"), b"stale");
    engine.close().unwrap();
    let engine = Engine::open(data.path()).unwrap();
    assert!(!data.path().join("tmp/deadbeef").exists(), "stale swept");
    assert!(spool_file.exists(), "live spool file kept");
    engine.close().unwrap();

    // rebuild drops temp ⇒ spool emptied
    fs::remove_file(data.path().join("index.db")).unwrap();
    let engine = Engine::open(data.path()).unwrap();
    assert!(!spool_file.exists(), "rebuild emptied the spool");
    engine.close().unwrap();
}

// §10.x — bindings survive rebuild (they are log events)
#[test]
fn bindings_survive_rebuild() {
    let (data, fixture, mut engine, folder) = bound_fixture(HashPolicy::Lazy);
    engine.scan(Some(&folder)).unwrap();
    engine.close().unwrap();
    fs::remove_file(data.path().join("index.db")).unwrap();
    let mut engine = Engine::open(data.path()).unwrap();
    let bindings = engine.bindings().unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].folder_id, folder);
    // post-rebuild scan re-matches by recorded locations: nothing re-added
    write_file(&fixture.path().join("movies/gamma.mkv"), b"gamma");
    let r = engine.scan(Some(&folder)).unwrap();
    assert_eq!(r[0].stats.added, 1, "only the genuinely new file");
    assert_eq!(r[0].stats.changed, 0);
    engine.close().unwrap();
}

// binding validation rules
#[test]
fn binding_rules() {
    let (_data, fixture, mut engine, folder) = bound_fixture(HashPolicy::Lazy);
    // double-bind refused
    assert!(matches!(
        engine.bind_folder(&folder, bind_spec(fixture.path(), HashPolicy::Lazy)),
        Err(PvfsError::BadInput { .. })
    ));
    // same dir on another folder refused
    let root = engine.identity.root_node_id.clone();
    let other = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "other".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    assert!(matches!(
        engine.bind_folder(&other, bind_spec(fixture.path(), HashPolicy::Lazy)),
        Err(PvfsError::BadInput { .. })
    ));
    // unbind then rebind elsewhere works
    engine.unbind_folder(&folder).unwrap();
    engine
        .bind_folder(&other, bind_spec(fixture.path(), HashPolicy::Lazy))
        .unwrap();
}
