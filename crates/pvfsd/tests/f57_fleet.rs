//! F5.7 (doc 17 §7.8): the self-teaching swarm. A holder publishes its
//! dial address into `.fleet/endpoints/<pin>` (write-through, like every
//! replica mutation), and every member's fetcher resolves location pins
//! it has no registry entry for FROM THE CATALOG — one bootstrap entry
//! and the fleet teaches itself. The local registry always wins.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::fetch::{catalog_endpoints, Fetcher, ENDPOINTS_DIR, FLEET_DIR};
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
fn fleet_teaches_new_members_the_holders() {
    // Empty local registry — the whole point: no `instance add` anywhere.
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());

    // ── owner: a file whose ONLY location is a holder pin ──────────────
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let holder_pin = "1b".repeat(32);
    let file = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "far.mkv".into(),
                payload: FilePayload {
                    content_hash: blake3::hash(b"far").to_hex().to_string(),
                    size_bytes: 3,
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
        .add_location(&file, &format!("pvfs-host://{holder_pin}/mnt/local/far.mkv"))
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

    // ── the holder box announces (the CLI's exact write shape) ─────────
    let fleet = rep.mkdir(&root, FLEET_DIR, sign).unwrap();
    let eps = rep.mkdir(&fleet, ENDPOINTS_DIR, sign).unwrap();
    rep.add_node(&eps, &holder_pin, "fleet.endpoint", b"10.0.0.9:7777", sign)
        .unwrap();

    // ── a brand-new member: replica + EMPTY registry ───────────────────
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
    let replica = Engine::open(&data_dir).unwrap();

    // The catalog teaches the address book…
    let eps_map = catalog_endpoints(&replica);
    assert_eq!(
        eps_map.get(&holder_pin).map(String::as_str),
        Some("10.0.0.9:7777"),
        "endpoint directory readable from the synced catalog"
    );

    // …and the fetcher resolves the holder with NO registry entry: the
    // catalog-taught candidate first, then the replica source fallback.
    let mut fetcher = Fetcher::new(&data_dir);
    let cands = fetcher.candidates(&replica, &file);
    assert!(
        cands
            .iter()
            .any(|c| c.transport == "tcp" && c.target == "10.0.0.9:7777" && c.pin == holder_pin),
        "catalog-taught holder is a candidate: {:?}",
        cands.iter().map(|c| c.target.clone()).collect::<Vec<_>>()
    );

    // The local registry always wins: same pin, operator-set address.
    std::fs::create_dir_all(cfg.path().join("pvfs")).unwrap();
    std::fs::write(
        cfg.path().join("pvfs/instances"),
        format!("holder 192.168.9.9:1111 {holder_pin}\n"),
    )
    .unwrap();
    let mut fetcher2 = Fetcher::new(&data_dir);
    let cands2 = fetcher2.candidates(&replica, &file);
    assert!(
        cands2.iter().any(|c| c.target == "192.168.9.9:1111" && c.pin == holder_pin),
        "registry overrides the catalog: {:?}",
        cands2.iter().map(|c| c.target.clone()).collect::<Vec<_>>()
    );
    assert!(
        !cands2.iter().any(|c| c.target == "10.0.0.9:7777"),
        "no duplicate candidate for the same pin"
    );
}
