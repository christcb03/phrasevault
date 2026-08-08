//! F2 — replica forests end-to-end (doc 17 §5): admin-gated log shipping,
//! chain-verified ingest, the fully verified replay at open, identical ACL
//! answers from the replica, read-only enforcement, and tail sync.

use std::io::Write as _;
use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::log_store::EventRow;
use pvfs_core::{
    crypto, identity, Engine, FilePayload, NodeSpec, PvfsError, ReplicaSource, ReplicaStore,
    TYPE_FILE, TYPE_FOLDER,
};
use pvfsd::{serve, Daemon};

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

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

/// Pull the full source log through the wire in small batches (exercises
/// batching) into a `ReplicaStore` at `data_dir`.
fn pull_all(client: &mut Client, data_dir: &std::path::Path, from: u64) -> u64 {
    let mut store = ReplicaStore::open(data_dir).unwrap();
    let mut from = from;
    let mut total = 0;
    loop {
        let (_tip, events) = client.log_read(from, 3).unwrap();
        if events.is_empty() {
            return total;
        }
        total += events.len() as u64;
        from = store.append(&wire_to_rows(&events)).unwrap() + 1;
    }
}

#[test]
fn replica_end_to_end() {
    // ---- the owner forest: shared/ (public r) with a real file, private/
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let forest_id = engine.identity.forest_id.clone();
    let shared = engine.add_node(&root, folder("shared")).unwrap();
    let private = engine.add_node(&root, folder("private")).unwrap();
    let _secret = engine.add_node(&private, folder("secret")).unwrap();

    let bytes_dir = tempfile::tempdir().unwrap();
    let clip_path = bytes_dir.path().join("clip.mkv");
    std::fs::File::create(&clip_path)
        .unwrap()
        .write_all(b"movie-bytes")
        .unwrap();
    let clip = engine
        .add_node(
            &shared,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "clip.mkv".into(),
                payload: FilePayload {
                    content_hash: blake3::hash(b"movie-bytes").to_hex().to_string(),
                    size_bytes: 11,
                    mime_type: "video/x-matroska".into(),
                    original_name: "clip.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine
        .add_location(
            &clip,
            &pvfs_core::storage::path_to_uri(&std::fs::canonicalize(&clip_path).unwrap()).unwrap(),
        )
        .unwrap();

    // replicator: admin on root (the replication gate) + w for the sync test
    let rep_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let rep_pub = crypto::pubkey_bytes(&rep_key);
    engine.authorize_member(&owner_mn, &rep_pub).unwrap();
    engine
        .set_acl(&root, &Principal::Key(rep_pub.clone()), acl::ACL_RWA)
        .unwrap();
    // a plain member without admin — must NOT pass the gate
    let mem_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let mem_pub = crypto::pubkey_bytes(&mem_key);
    engine.authorize_member(&owner_mn, &mem_pub).unwrap();
    engine
        .set_acl(&shared, &Principal::Public, acl::ACL_R)
        .unwrap();

    // ---- serve on a unix socket
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

    // ---- the gate: anon and non-admin members are refused
    let mut anon = Client::connect_public(&sock).unwrap();
    assert!(
        matches!(anon.log_info(), Err(ClientError::Server { code, .. }) if code == "forbidden"),
        "anonymous log shipping must be forbidden"
    );
    let mut member = Client::connect_signed(&sock, &mem_pub, |d| {
        crypto::sign_digest(&mem_key, d).unwrap()
    })
    .unwrap();
    assert!(
        matches!(member.log_read(1, 10), Err(ClientError::Server { code, .. }) if code == "forbidden"),
        "non-admin member log shipping must be forbidden"
    );

    // ---- replicate as the root-admin member
    let mut rep = Client::connect_signed(&sock, &rep_pub, |d| {
        crypto::sign_digest(&rep_key, d).unwrap()
    })
    .unwrap();
    let tip = rep.log_info().unwrap();
    assert!(tip > 0);

    let replica_mount = tempfile::tempdir().unwrap();
    let data_dir = replica_mount.path().join(".pvfs");
    let shipped = pull_all(&mut rep, &data_dir, 1);
    assert_eq!(shipped, tip, "full log shipped");
    ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
    }
    .save(&data_dir)
    .unwrap();

    // ---- open = the verified replay; Engine::open routes the marker
    let replica = Engine::open(&data_dir).unwrap();
    assert!(replica.is_replica());
    assert_eq!(replica.identity.forest_id, forest_id);
    assert_eq!(replica.identity.root_node_id, root);
    let labels: Vec<String> = replica
        .walk(&root)
        .unwrap()
        .entries
        .into_iter()
        .map(|e| e.node.label)
        .collect();
    assert!(labels.contains(&"shared".to_string()) && labels.contains(&"secret".to_string()));

    // ACL answers are identical on the replica (the grants ARE the log)
    assert_ne!(
        replica
            .effective_rights(&Principal::Public, &shared)
            .unwrap()
            & acl::ACL_R,
        0,
        "public read on /shared holds on the replica"
    );
    assert_eq!(
        replica
            .effective_rights(&Principal::Public, &private)
            .unwrap(),
        0,
        "no public rights on /private on the replica"
    );

    // same-host locations resolve: the replica serves the actual bytes (F0+F2)
    let mut out = Vec::new();
    let mut replica = replica;
    replica.cat(&clip, None, &mut out).unwrap();
    assert_eq!(out, b"movie-bytes");

    // ---- read-only: local writes refuse
    let err = replica.add_node(&root, folder("intruder")).unwrap_err();
    assert!(
        matches!(err, PvfsError::Forbidden { .. }),
        "replica must refuse local writes, got {err:?}"
    );
    replica.close().unwrap();

    // ---- tail sync: the replicator writes a folder via the daemon, then syncs
    let mut rep2 = Client::connect_signed(&sock, &rep_pub, |d| {
        crypto::sign_digest(&rep_key, d).unwrap()
    })
    .unwrap();
    rep2.mkdir(&root, "new-season", |d| {
        crypto::sign_digest(&rep_key, d).unwrap()
    })
    .unwrap();
    let synced = {
        let from = ReplicaStore::open(&data_dir).unwrap().tip().unwrap() + 1;
        pull_all(&mut rep2, &data_dir, from)
    };
    assert!(synced >= 1, "tail events shipped");
    let replica = Engine::open(&data_dir).unwrap();
    let labels: Vec<String> = replica
        .children(&root)
        .unwrap()
        .into_iter()
        .map(|c| c.node.label)
        .collect();
    assert!(labels.contains(&"new-season".to_string()), "synced tail folds: {labels:?}");
    replica.close().unwrap();
}

// F3 (doc 17 §6): a replica whose recorded location doesn't resolve locally
// — the cross-host case — pulls the bytes from its source, verified, into
// the managed sync store, and serves them from there.
#[test]
fn replica_sync_fetches_missing_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    let bytes_dir = tempfile::tempdir().unwrap();
    let path_a = bytes_dir.path().join("a").join("far.mkv");
    std::fs::create_dir_all(path_a.parent().unwrap()).unwrap();
    std::fs::File::create(&path_a)
        .unwrap()
        .write_all(b"far-bytes")
        .unwrap();
    let far = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "far.mkv".into(),
                payload: FilePayload {
                    content_hash: blake3::hash(b"far-bytes").to_hex().to_string(),
                    size_bytes: 9,
                    mime_type: "video/x-matroska".into(),
                    original_name: "far.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine
        .add_location(
            &far,
            &pvfs_core::storage::path_to_uri(&std::fs::canonicalize(&path_a).unwrap()).unwrap(),
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

    // replicate, then MOVE the bytes: the owner learns location B over the
    // daemon, but the replica's shipped log still names only the dead A —
    // exactly what a replica on another host sees.
    let replica_mount = tempfile::tempdir().unwrap();
    let data_dir = replica_mount.path().join(".pvfs");
    pull_all(&mut rep, &data_dir, 1);
    ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
    }
    .save(&data_dir)
    .unwrap();

    let path_b = bytes_dir.path().join("b").join("far.mkv");
    std::fs::create_dir_all(path_b.parent().unwrap()).unwrap();
    std::fs::rename(&path_a, &path_b).unwrap();
    rep.add_location(
        &far,
        &pvfs_core::storage::path_to_uri(&std::fs::canonicalize(&path_b).unwrap()).unwrap(),
        sign,
    )
    .unwrap();

    let mut replica = Engine::open(&data_dir).unwrap();
    let missing = replica.missing_bytes(&root).unwrap();
    assert_eq!(missing.len(), 1, "far.mkv has no readable location locally");
    assert_eq!(missing[0].1, "far.mkv");

    // fetch through the source daemon into the sync store, hash-verified
    let mut fetcher = Client::connect_signed(&sock, &rep_pub, sign).unwrap();
    let mut sink = replica.sync_begin(&far).unwrap();
    fetcher.cat(&far, &mut sink).unwrap();
    replica.sync_commit(sink).unwrap();

    assert!(replica.missing_bytes(&root).unwrap().is_empty());
    let mut out = Vec::new();
    replica.cat(&far, None, &mut out).unwrap();
    assert_eq!(out, b"far-bytes");
    assert!(replica
        .locations(&far)
        .unwrap()
        .iter()
        .any(|u| u.starts_with("pvfs-sync:///")));
    replica.close().unwrap();
}

// a tampered shipped row fails ingest at the exact seq
#[test]
fn tampered_ship_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    engine.add_node(&root, folder("a")).unwrap();
    let rows: Vec<EventRow> = {
        let tip = engine.log_tip().unwrap();
        engine.log_events(1, tip as usize).unwrap()
    };
    engine.close().unwrap();

    let mut rows = rows;
    let last = rows.len() - 1;
    rows[last].body[0] ^= 0x01; // flip one byte in the newest event

    let store_dir = tempfile::tempdir().unwrap();
    let mut store = ReplicaStore::open(&store_dir.path().join(".pvfs")).unwrap();
    let err = store.append(&rows).unwrap_err();
    assert!(
        matches!(err, PvfsError::LogChainBroken { seq, .. } if seq == rows[last].seq),
        "chain break must be caught at the tampered seq, got {err:?}"
    );
}
