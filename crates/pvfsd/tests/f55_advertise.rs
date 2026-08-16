//! F5.5 (doc 17 §7.7): advertised holders — the round trip. A replica
//! syncs a file, ADVERTISES its store copy as an own-pin location
//! (write-through, visible fleet-wide), and later — when the subtree
//! leaves advertise placement — RETRACTS it before deleting bytes.
//! Modeled on `replica.rs`'s sync test; the D69 lab found the gap.

use std::io::Write as _;
use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::advertise::{advertise_pass, retract_pass, BoxedSign};
use pvfs_client::Client;
use pvfs_core::acl::{self, Principal};
use pvfs_core::log_store::EventRow;
use pvfs_core::{
    crypto, identity, Engine, FilePayload, NodeSpec, ReplicaSource, ReplicaStore, TYPE_FILE,
};
use pvfsd::{serve, Daemon};

fn wire_to_rows(events: &[pvfs_client::LogEventWire]) -> Vec<EventRow> {
    events
        .iter()
        .map(|w| EventRow {
            seq: w.seq,
            kind: w.kind.clone(),
            body: hex::decode(&w.body).unwrap(),
            chain_hash: hex::decode(&w.chain_hash).unwrap(),
            written_at: w.written_at,
        })
        .collect()
}

fn pull_all(client: &mut Client, data_dir: &std::path::Path, from: u64) -> u64 {
    let mut store = ReplicaStore::open(data_dir).unwrap();
    let mut from = from;
    let mut total = 0;
    loop {
        let (_tip, events) = client.log_read(from, 64, "").unwrap();
        if events.is_empty() {
            return total;
        }
        total += events.len() as u64;
        from = store.append(&wire_to_rows(&events)).unwrap() + 1;
    }
}

#[test]
fn advertise_then_retract_round_trip() {
    // ── owner: a file with local bytes; a replicator enrolled rwa ──────
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    let bytes_dir = tempfile::tempdir().unwrap();
    let src_path = bytes_dir.path().join("show.mkv");
    std::fs::File::create(&src_path)
        .unwrap()
        .write_all(b"advertised-bytes")
        .unwrap();
    let file = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "show.mkv".into(),
                payload: FilePayload {
                    content_hash: blake3::hash(b"advertised-bytes").to_hex().to_string(),
                    size_bytes: 16,
                    mime_type: "video/x-matroska".into(),
                    original_name: "show.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine
        .add_location(
            &file,
            &pvfs_core::storage::path_to_uri(&std::fs::canonicalize(&src_path).unwrap()).unwrap(),
        )
        .unwrap();

    let rep_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let rep_pub = crypto::pubkey_bytes(&rep_key);
    engine.authorize_member(&owner_mn, &rep_pub).unwrap();
    engine
        .set_acl(&root, &Principal::Key(rep_pub.clone()), acl::ACL_RWA)
        .unwrap();

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(engine));
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let sign = |d: &[u8; 32]| crypto::sign_digest(&rep_key, d).unwrap();
    let mut rep = Client::connect_signed(&sock, &rep_pub, sign).unwrap();

    // ── the replica box: pull, fake a transport pin, place advertise ───
    let replica_mount = tempfile::tempdir().unwrap();
    let data_dir = replica_mount.path().join(".pvfs");
    pull_all(&mut rep, &data_dir, 1);
    ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    }
    .save(&data_dir)
    .unwrap();
    let pin = "ab".repeat(32); // host_pin: 64 hex — pvfsd --listen writes this
    std::fs::create_dir_all(data_dir.join("nettls")).unwrap();
    std::fs::write(data_dir.join("nettls/pin"), &pin).unwrap();
    pvfs_core::sync::set_sync_mode(&data_dir, &root, true, true).unwrap();

    // fetch into the sync store (the replica.rs pattern)
    let mut replica = Engine::open(&data_dir).unwrap();
    let mut fetcher = Client::connect_signed(&sock, &rep_pub, sign).unwrap();
    let mut sink = replica.sync_begin(&file).unwrap();
    fetcher.cat(&file, &mut sink).unwrap();
    replica.sync_commit(sink).unwrap();

    replica.close().unwrap();

    // ── advertise: the store copy becomes a fleet-visible location ─────
    let mut route_client = Client::connect_signed(&sock, &rep_pub, sign).unwrap();
    let key_owned = rep_key.clone();
    let sign_box: BoxedSign = Box::new(move |d| crypto::sign_digest(&key_owned, d).unwrap());
    let report = advertise_pass(&data_dir, Some((&mut route_client, &*sign_box))).unwrap();
    assert_eq!(report.advertised, 1, "the synced copy advertises: {:?}", report.skipped);

    // idempotent: a second pass logs nothing new (catch-up folded the tail)
    let again = advertise_pass(&data_dir, Some((&mut route_client, &*sign_box))).unwrap();
    assert_eq!(again.advertised, 0, "re-runs are catch-up, not duplicates");

    let replica = Engine::open(&data_dir).unwrap();
    let locs = replica.locations(&file).unwrap();
    let advertised = locs
        .iter()
        .find(|u| u.starts_with(&format!("pvfs-host://{pin}/")))
        .cloned()
        .expect("own-pin location logged fleet-wide");
    assert!(
        advertised.contains("synced"),
        "the advertised path is the sync-store copy: {advertised}"
    );
    drop(replica);

    // ── leave placement; retract-and-reclaim ────────────────────────────
    pvfs_core::sync::set_sync_mode(&data_dir, &root, false, false).unwrap();
    let r = retract_pass(&data_dir, Some((&mut route_client, &*sign_box))).unwrap();
    assert_eq!(r.retracted, 1, "de-placed advertised copy retracts: {:?}", r.skipped);
    assert!(r.freed_bytes > 0, "bytes reclaimed");
    assert!(
        pvfs_core::sync::sync_store_lookup(&data_dir, &file).unwrap().is_none()
            || !replica_mount.path().join(".pvfs/synced").exists()
            || r.freed_bytes == 16,
        "store copy gone"
    );

    // the retraction is fleet truth too — and the original survives
    let replica = Engine::open(&data_dir).unwrap();
    let locs = replica.locations(&file).unwrap();
    assert!(
        !locs.iter().any(|u| u.starts_with("pvfs-host://ab")),
        "advertisement retracted: {locs:?}"
    );
    assert!(
        locs.iter().any(|u| u.starts_with("file://")),
        "the owner's original location was never touched"
    );
}

#[test]
fn retract_keeps_bytes_when_theirs_is_the_only_location() {
    // A file whose ONLY location is the advertisement must never lose its
    // bytes — the skip carries the reason, the store copy stays.
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let file = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "only-here.mkv".into(),
                payload: FilePayload {
                    content_hash: blake3::hash(b"lonely").to_hex().to_string(),
                    size_bytes: 6,
                    mime_type: "video/x-matroska".into(),
                    original_name: "only-here.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    let _ = owner_mn;

    // Owner-local flavor of the pass (route = None): fake the pin, put
    // verified bytes in the store via the engine's own seam, advertise,
    // then de-place and try to retract.
    let data_dir = engine.data_dir().to_path_buf();
    let pin = "cd".repeat(32);
    std::fs::create_dir_all(data_dir.join("nettls")).unwrap();
    std::fs::write(data_dir.join("nettls/pin"), &pin).unwrap();
    let mut sink = engine.sync_begin(&file).unwrap();
    sink.write_all(b"lonely").unwrap();
    engine.sync_commit(sink).unwrap();

    engine.close().unwrap();
    pvfs_core::sync::set_sync_mode(&data_dir, &root, true, true).unwrap();
    let report = advertise_pass(&data_dir, None).unwrap();
    assert_eq!(report.advertised, 1, "{:?}", report.skipped);

    pvfs_core::sync::set_sync_mode(&data_dir, &root, false, false).unwrap();
    let r = retract_pass(&data_dir, None).unwrap();
    assert_eq!(r.retracted, 0, "sole location is never deleted");
    assert_eq!(r.skipped.len(), 1, "and the hold is reported: {:?}", r.skipped);
    assert!(
        pvfs_core::sync::sync_store_lookup(&data_dir, &file).unwrap().is_some(),
        "bytes kept"
    );
    // the advertisement stays too — still true, still serving
    let engine = Engine::open(&data_dir).unwrap();
    assert!(engine
        .locations(&file)
        .unwrap()
        .iter()
        .any(|u| u.starts_with(&format!("pvfs-host://{pin}/"))));
}

#[test]
fn tier_logs_served_by_attribution_and_never_retires_it() {
    // The mover with `--served-by`: the store copy is logged twice — the
    // owner-local file:// row AND the serving instance's pvfs-host:// row
    // (same aa/<id> layout under its remote prefix) — and the retire step
    // must NOT treat that attribution row as an edge copy (the bug the
    // code read-through caught: foreign pin ⇒ retired in the same pass).
    let cfg = tempfile::tempdir().unwrap();
    // Scratch instance registry (identity::config_dir honors this); the
    // sibling tests never read it, so the process-global env is safe here.
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let nas_pin = "ef".repeat(32);
    std::fs::create_dir_all(cfg.path().join("pvfs")).unwrap();
    std::fs::write(
        cfg.path().join("pvfs/instances"),
        format!("nas 127.0.0.1:1 {nas_pin}\n"),
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let bytes_dir = tempfile::tempdir().unwrap();
    let src = bytes_dir.path().join("movie.mkv");
    std::fs::File::create(&src).unwrap().write_all(b"store-me").unwrap();
    let file = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "movie.mkv".into(),
                payload: FilePayload {
                    content_hash: blake3::hash(b"store-me").to_hex().to_string(),
                    size_bytes: 8,
                    mime_type: "video/x-matroska".into(),
                    original_name: "movie.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    // The ingest-box shape (what migrates): the ONLY logged location is a
    // foreign edge pin — owner-local bytes would read as already-central.
    // The bytes are reachable through the sync store (no network in a
    // unit test), which deliberately never counts as a central copy.
    let edge_pin = "aa".repeat(32);
    engine
        .add_location(&file, &format!("pvfs-host://{edge_pin}/mnt/local/movie.mkv"))
        .unwrap();
    let mut sink = engine.sync_begin(&file).unwrap();
    sink.write_all(b"store-me").unwrap();
    engine.sync_commit(sink).unwrap();
    drop(src);

    let store = tempfile::tempdir().unwrap();
    pvfs_core::sync::set_central_served(
        engine.data_dir(),
        &root,
        store.path(),
        false,
        Some(("nas", std::path::Path::new("/share/CACHEDEV1_DATA/pvfs-store"))),
    )
    .unwrap();

    let data_dir = engine.data_dir().to_path_buf();
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    let report = pvfs_client::fetch::tier_pass(&mut engine, &mut fetcher)
        .unwrap()
        .expect("central placement exists");
    assert_eq!(report.migrated, 1, "failed: {:?}", report.failed);

    let locs = engine.locations(&file).unwrap();
    let shard = &file[..2];
    let expect_remote =
        format!("pvfs-host://{nas_pin}/share/CACHEDEV1_DATA/pvfs-store/{shard}/{file}");
    assert!(
        locs.iter().any(|u| u == &expect_remote),
        "the attribution row is logged: {locs:?}"
    );
    assert!(
        locs.iter().any(|u| u.starts_with("file://") && u.contains(&format!("/{shard}/"))),
        "the owner-local store row is logged too: {locs:?}"
    );

    // The retire step ran in the SAME pass: the edge row died, the
    // attribution row survived (it is the store, not an edge copy) —
    // the exact bug the code read-through caught.
    assert!(
        !locs.iter().any(|u| u.contains(&edge_pin)),
        "the edge copy was retired: {locs:?}"
    );

    // A second pass: satisfied, and the attribution row still stands.
    let report2 = pvfs_client::fetch::tier_pass(&mut engine, &mut fetcher)
        .unwrap()
        .unwrap();
    assert_eq!(report2.satisfied, 1);
    let locs2 = engine.locations(&file).unwrap();
    assert!(
        locs2.iter().any(|u| u == &expect_remote),
        "attribution survives the retire step: {locs2:?}"
    );
}
