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
    let (_data, _fixture, mut engine, folder) = bound_fixture(HashPolicy::OnAdd);
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
    let mut spec = bind_spec(fixture.path(), HashPolicy::OnAdd);
    spec.extensions = "mkv".into();
    engine.bind_folder(&folder, spec).unwrap();
    let r = engine.scan(Some(&folder)).unwrap();
    assert_eq!(r[0].stats.added, 1);
    assert_eq!(r[0].stats.skipped, 1);
    assert!(find_by_label(&engine, &folder, "b.txt").is_none());
}

// Our own sidecars are never content. An empty extension list means "every file
// the operator has" — adopting a `.manifest` makes the next pass write a sidecar
// for the sidecar, one level deeper each time (23 deep in the field, 2026-08-29).
// Not counted as `skipped`: ours is not something the operator declined to index.
#[test]
fn scan_never_adopts_manifest_sidecars() {
    let (_data, mut engine, _m) = new_forest();
    let fixture = tempfile::tempdir().unwrap();
    write_file(&fixture.path().join("alpha.mkv"), b"alpha-bytes");
    write_file(&fixture.path().join("alpha.mkv.manifest"), b"pvfs-manifest 1\n");
    write_file(
        &fixture.path().join("alpha.mkv.manifest.manifest"),
        b"pvfs-manifest 1\n",
    );
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
    // the production shape: no extension filter at all
    engine
        .bind_folder(&folder, bind_spec(fixture.path(), HashPolicy::OnAdd))
        .unwrap();

    let r = engine.scan(Some(&folder)).unwrap();
    assert_eq!(r[0].stats.skipped, 0, "our bookkeeping is not a skip");
    assert!(find_by_label(&engine, &folder, "alpha.mkv").is_some());
    assert!(
        find_by_label(&engine, &folder, "alpha.mkv.manifest").is_none(),
        "sidecar must never become content"
    );
    assert!(find_by_label(&engine, &folder, "alpha.mkv.manifest.manifest").is_none());
}

// import never references a file the operator cannot read (doc 05 §5.1)
#[cfg(unix)]
#[test]
fn unreadable_file_is_not_imported() {
    use std::os::unix::fs::PermissionsExt;

    let (_data, mut engine, _m) = new_forest();
    let fixture = tempfile::tempdir().unwrap();
    write_file(&fixture.path().join("readable.txt"), b"ok");
    let secret = fixture.path().join("secret.txt");
    write_file(&secret, b"nope");
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();

    // If this process can still open a 000 file (running as root / CAP_DAC_OVERRIDE),
    // access(2) is a no-op and there is nothing to enforce — assert accordingly.
    let enforced = fs::File::open(&secret).is_err();

    let root = engine.identity.root_node_id.clone();
    let folder = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "lib".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine
        .bind_folder(&folder, bind_spec(fixture.path(), HashPolicy::OnAdd))
        .unwrap();

    let r = engine.scan(Some(&folder)).unwrap();
    assert!(find_by_label(&engine, &folder, "readable.txt").is_some());
    if enforced {
        assert_eq!(r[0].stats.added, 1, "only the readable file is imported");
        assert_eq!(r[0].stats.unreadable, 1, "the 000 file is reported unreadable");
        assert!(find_by_label(&engine, &folder, "secret.txt").is_none());
    } else {
        assert_eq!(r[0].stats.added, 2);
    }

    // restore perms so the tempdir can be cleaned up
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
}

// §10.4 — disk deletion soft-removes; restore re-attaches the same node
#[test]
fn disk_delete_and_restore() {
    let (_data, fixture, mut engine, folder) = bound_fixture(HashPolicy::OnAdd);
    engine.scan(Some(&folder)).unwrap();
    let notes = find_by_label(&engine, &folder, "notes.txt").unwrap();

    fs::remove_file(fixture.path().join("notes.txt")).unwrap();
    let r = engine.scan(Some(&folder)).unwrap();
    assert_eq!(r[0].stats.removed, 1, "the location goes");
    assert!(engine.locations(&notes).unwrap().is_empty());

    // D105 — and because that was its LAST location on a mount whose marker
    // verified, the link goes too: the file is gone, so the node leaves the
    // tree. Before D105 the node stayed, listed to anyone browsing, waiting
    // for a manual `missing --forget` that in production nobody ran (1,849
    // such nodes from a single folder — doc 24 section 18).
    //
    // D112 — but not on THIS pass. Held-nowhere is an observation, and on a
    // fleet whose mover works outside the catalogue it is a routine transient
    // one, so the node leaves only if it is still unheld a day later. The
    // no-second-manual-step property is intact; the timing is not immediate.
    assert_eq!(r[0].stats.unlinked, 0, "not yet — the grace is running");
    assert_eq!(r[0].stats.pending_unlink, 1, "and the wait is visible");
    {
        let conn = rusqlite::Connection::open(engine.data_dir().join("index.db")).unwrap();
        conn.execute(
            "UPDATE scan_unheld SET since_ms = since_ms - ?1",
            rusqlite::params![(pvfs_core::UNLINK_GRACE_MS + 60_000) as i64],
        )
        .unwrap();
    }
    let r = engine.scan(Some(&folder)).unwrap();
    assert_eq!(r[0].stats.unlinked, 1, "and the node leaves the tree with it");

    // The EVENT history is still there — unlink is a soft remove on an
    // append-only log, so this is reversible and nothing was destroyed.
    assert!(
        engine.get_node(&notes).unwrap().is_some(),
        "the node record survives; only its place in the tree is gone"
    );

    // Restoring the bytes re-catalogues the file — under a NEW node.
    //
    // This is the cost of D105 and it is deliberate. `match_by_identity`
    // matches only nodes with a live containing link, on the stated grounds
    // that "a deletion is a decision, and the same bytes arriving later are
    // new". Before D105 the link survived a delete, so this path was never
    // reached and a restore silently revived the old node. Now it is reached,
    // and the file comes back with a new identity.
    //
    // A MOVE is not affected: removals run after additions, so the new
    // location is recorded before the old one is retired and the node never
    // reaches zero locations.
    write_file(&fixture.path().join("notes.txt"), b"hello notes");
    let r = engine.scan(Some(&folder)).unwrap();
    assert_eq!(r[0].stats.added, 1);
    let restored = find_by_label(&engine, &folder, "notes.txt").unwrap();
    assert_ne!(restored, notes, "a restored file is a new node, not a revival");
    assert_eq!(engine.locations(&restored).unwrap().len(), 1);
    assert!(!engine.stat_node(&restored).unwrap().unavailable);
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
    let (_data, fixture, mut engine, folder) = bound_fixture(HashPolicy::OnAdd);
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
    // D94 — `Never` is now how you get an UNHASHED node on purpose. This test
    // is about filling a hash that is absent, which `on_add` no longer leaves.
    let (_data, _fixture, mut engine, folder) = bound_fixture(HashPolicy::Never);
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
    let (data, fixture, mut engine, folder) = bound_fixture(HashPolicy::OnAdd);
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
    let (_data, fixture, mut engine, folder) = bound_fixture(HashPolicy::OnAdd);
    // double-bind refused
    assert!(matches!(
        engine.bind_folder(&folder, bind_spec(fixture.path(), HashPolicy::OnAdd)),
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
        engine.bind_folder(&other, bind_spec(fixture.path(), HashPolicy::OnAdd)),
        Err(PvfsError::BadInput { .. })
    ));
    // unbind then rebind elsewhere works
    engine.unbind_folder(&folder, None).unwrap();
    engine
        .bind_folder(&other, bind_spec(fixture.path(), HashPolicy::OnAdd))
        .unwrap();
}

// D93 — the backfill rescues hashes that exist only in the catalog.
//
// Before D91 the fill wrote the hash into the node and NOTHING to disk, so tens
// of hours of holder time were pinned to one forest: 3005 hashed nodes against
// 90 sidecars. This is the job that gets that work out where a re-import can
// use it, and it must never stamp an old hash beside bytes that have changed.
#[test]
fn backfill_rescues_catalog_only_hashes() {
    let (_data, mut engine, _m) = new_forest();
    let fixture = tempfile::tempdir().unwrap();
    write_file(&fixture.path().join("alpha.mkv"), b"alpha-bytes");
    write_file(&fixture.path().join("beta.mkv"), b"beta-bytes!");
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
        .bind_folder(&folder, bind_spec(fixture.path(), HashPolicy::OnAdd))
        .unwrap();
    engine.scan(Some(&folder)).unwrap();

    // The pre-D91 world, reconstructed: the catalog knows the hash, disk does not.
    let alpha = fixture.path().join("alpha.mkv");
    let beta = fixture.path().join("beta.mkv");
    for f in [&alpha, &beta] {
        let _ = std::fs::remove_file(pvfs_core::sync::manifest_sidecar_path(f));
    }
    assert!(pvfs_core::sync::sidecar_whole_hash(&alpha, 11).is_none());

    let dry = engine.backfill_sidecars(true).unwrap();
    assert_eq!(dry.written, 2, "dry run counts both");
    assert!(
        pvfs_core::sync::sidecar_whole_hash(&alpha, 11).is_none(),
        "a dry run must write nothing"
    );

    let r = engine.backfill_sidecars(false).unwrap();
    assert_eq!(r.written, 2);
    let rescued = pvfs_core::sync::sidecar_whole_hash(&alpha, 11).expect("hash now on disk");
    assert_eq!(rescued, blake3::hash(b"alpha-bytes").to_hex().to_string());

    // idempotent — a second pass has nothing left to do
    let again = engine.backfill_sidecars(false).unwrap();
    assert_eq!(again.written, 0);
    assert_eq!(again.already_durable, 2);

    // THE SAFETY CASE: bytes replaced at the same path. This job writes hashes
    // it did not compute, so asserting one for bytes that have since changed is
    // the single way it can do real damage — and the lie would be carried into
    // the fresh forest as truth.
    let _ = std::fs::remove_file(pvfs_core::sync::manifest_sidecar_path(&beta));
    write_file(&beta, b"a completely different encode");
    let after = engine.backfill_sidecars(false).unwrap();
    assert_eq!(after.written, 0, "must not stamp a stale hash on new bytes");
    assert_eq!(after.size_mismatch, 1);
    assert!(pvfs_core::sync::sidecar_whole_hash(&beta, 29).is_none());
}
