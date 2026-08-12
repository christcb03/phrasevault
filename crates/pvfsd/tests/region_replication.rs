//! P7.2b (doc 20 §2.4) — region-generation replication over the wire:
//! whole-forest replicas ship every region log, scoped replicas tolerate
//! absent siblings, the region-root gate admits lesser-privilege region
//! reads, and a top-scoped LogWait wakes on region activity.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::log_store::EventRow;
use pvfs_core::{
    crypto, identity, Engine, NodeSpec, ReplicaSource, ReplicaStore, TYPE_FOLDER,
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

fn pull_top(client: &mut Client, data_dir: &std::path::Path) -> u64 {
    let mut store = ReplicaStore::open(data_dir).unwrap();
    let mut from = store.tip().unwrap() + 1;
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

/// Owner forest with: photos (active region, one child), docs (region that
/// was written into and then SEALED), music (plain top-region folder).
/// Returns (data_dir tempdir, admin key pair, node ids).
struct Fixture {
    _dir: tempfile::TempDir,
    _sockdir: tempfile::TempDir,
    sock: std::path::PathBuf,
    rep_key: identity::SigningKey,
    rep_pub: Vec<u8>,
    root: String,
    photos: String,
    photos_child: String,
    docs: String,
    docs_child: String,
    photos_addr: String,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let photos = engine.add_node(&root, folder("photos")).unwrap();
    let docs = engine.add_node(&root, folder("docs")).unwrap();
    let _music = engine.add_node(&root, folder("music")).unwrap();
    engine.region_mark(&photos).unwrap();
    let photos_child = engine.add_node(&photos, folder("summer")).unwrap();
    engine.region_mark(&docs).unwrap();
    let docs_child = engine.add_node(&docs, folder("letters")).unwrap();
    engine.region_unmark(&docs).unwrap(); // sealed generation with content

    let info = engine.region_info(&photos).unwrap().unwrap();
    let photos_addr =
        pvfs_core::replica::region_addr(&photos, &info.baseline_log, info.baseline_seq);

    // replication admin (forest root) — the whole-forest puller
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
    Fixture {
        _dir: dir,
        _sockdir: sockdir,
        sock,
        rep_key,
        rep_pub,
        root,
        photos,
        photos_child,
        docs,
        docs_child,
        photos_addr,
    }
}

fn admin_client(fx: &Fixture) -> Client {
    let key = fx.rep_key.clone();
    Client::connect_signed(&fx.sock, &fx.rep_pub, move |d| {
        crypto::sign_digest(&key, d).unwrap()
    })
    .unwrap()
}

#[test]
fn whole_forest_replica_ships_and_replays_region_logs() {
    let fx = fixture();
    let mut rep = admin_client(&fx);

    let mount = tempfile::tempdir().unwrap();
    let data_dir = mount.path().join(".pvfs");
    pull_top(&mut rep, &data_dir);
    ReplicaSource {
        transport: "socket".into(),
        target: fx.sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    }
    .save(&data_dir)
    .unwrap();
    let pulled = pvfs_client::regions::sync_generations(&mut rep, &data_dir, None).unwrap();
    assert!(pulled > 0, "region rows must ship");

    // the verified replay walks the tree: active + sealed regions fold
    let replica = Engine::open(&data_dir).unwrap();
    assert!(replica.is_replica());
    assert!(
        replica.get_node(&fx.photos_child).unwrap().is_some(),
        "active-region content replays on the replica"
    );
    assert!(
        replica.get_node(&fx.docs_child).unwrap().is_some(),
        "sealed-generation content replays on the replica"
    );
    assert!(
        replica.region_info(&fx.photos).unwrap().is_some(),
        "region generation state folds on the replica"
    );
    assert_eq!(replica.region_of(&fx.photos_child).unwrap(), fx.photos);
    replica.close().unwrap();
}

#[test]
fn scoped_replica_tolerates_absent_sibling_generations() {
    let fx = fixture();
    let mut rep = admin_client(&fx);

    let mount = tempfile::tempdir().unwrap();
    let data_dir = mount.path().join(".pvfs");
    pull_top(&mut rep, &data_dir);
    ReplicaSource {
        transport: "socket".into(),
        target: fx.sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: fx.photos.clone(),
    }
    .save(&data_dir)
    .unwrap();
    let pulled =
        pvfs_client::regions::sync_generations(&mut rep, &data_dir, Some(&fx.photos)).unwrap();
    assert!(pulled > 0, "the scoped region's rows must ship");

    // open must succeed even though docs' SEALED generation is absent —
    // it stays attested by the top log, unverifiable until fetched
    let replica = Engine::open(&data_dir).unwrap();
    assert!(
        replica.get_node(&fx.photos_child).unwrap().is_some(),
        "in-scope content present"
    );
    assert!(
        replica.get_node(&fx.docs_child).unwrap().is_none(),
        "out-of-scope sealed content stays unfetched"
    );
    assert!(
        replica.get_node(&fx.docs).unwrap().is_some(),
        "the sibling's root node itself lives in the top log"
    );
    replica.close().unwrap();
}

#[test]
fn region_gate_admits_region_admin_without_forest_rights() {
    let fx = fixture();
    // a member with admin on the photos region root only, admitted + granted
    // through the wire by the forest admin
    let mut owner_side = admin_client(&fx);
    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let pubkey = crypto::pubkey_bytes(&key);
    let admin_sign = {
        let k = fx.rep_key.clone();
        move |d: &[u8; 32]| crypto::sign_digest(&k, d).unwrap()
    };
    owner_side
        .authorize_member(&hex::encode(&pubkey), &admin_sign)
        .unwrap();
    owner_side
        .set_acl(
            &fx.photos,
            &format!("key:{}", hex::encode(&pubkey)),
            "rwa",
            &admin_sign,
        )
        .unwrap();

    let mut member = Client::connect_signed(&fx.sock, &pubkey, move |d| {
        crypto::sign_digest(&key, d).unwrap()
    })
    .unwrap();
    assert!(
        matches!(member.log_read(1, 10, ""), Err(ClientError::Server { code, .. }) if code == "forbidden"),
        "region admin must NOT ship the top log"
    );
    let (tip, events) = member.log_read(1, 64, &fx.photos_addr).unwrap();
    assert!(tip > 0 && !events.is_empty(), "region admin ships the region log");

    // anonymous stays out of region logs too
    let mut anon = Client::connect_public(&fx.sock).unwrap();
    assert!(
        matches!(anon.log_read(1, 10, &fx.photos_addr), Err(ClientError::Server { code, .. }) if code == "forbidden"),
        "anonymous region shipping must be forbidden"
    );
    let _ = fx.root;
}

#[test]
fn cross_region_move_over_the_wire_replays_and_replicates() {
    // P7.2c (doc 20 §2.5): a wire mv across a boundary authors the paired
    // protocol; every later engine open replays the pair (destination log
    // first — the convergence order), and a whole-forest replica reproduces
    // the move from shipped logs alone.
    let fx = fixture();
    let mut writer = admin_client(&fx);
    let k = fx.rep_key.clone();
    let sign = move |d: &[u8; 32]| crypto::sign_digest(&k, d).unwrap();

    // photos_child leaves its region for the top-region root, then a fresh
    // SUBTREE (wanderer/cargo) makes the reverse crossing — descendants'
    // sticky regions must follow the move (doc 20 §2.5)
    writer.mv(&fx.photos_child, &fx.root, &sign).unwrap();
    let wanderer = writer.mkdir(&fx.root, "wanderer", &sign).unwrap();
    let cargo = writer.mkdir(&wanderer, "cargo", &sign).unwrap();
    writer.mv(&wanderer, &fx.photos, &sign).unwrap();

    // a second engine open on the owner dir = full tree replay of the pairs
    let owner_dir = fx._dir.path().to_path_buf();
    let e = Engine::open(&owner_dir).unwrap();
    assert_eq!(
        e.region_of(&fx.photos_child).unwrap(),
        e.identity.root_node_id,
        "moved-out node joined the top region"
    );
    assert_eq!(
        e.region_of(&wanderer).unwrap(),
        fx.photos,
        "moved-in node joined the destination region"
    );
    assert_eq!(
        e.region_of(&cargo).unwrap(),
        fx.photos,
        "the moved subtree's descendants follow (source-first replay order)"
    );
    drop(e);

    // and the whole story replicates
    let mount = tempfile::tempdir().unwrap();
    let data_dir = mount.path().join(".pvfs");
    pull_top(&mut writer, &data_dir);
    ReplicaSource {
        transport: "socket".into(),
        target: fx.sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    }
    .save(&data_dir)
    .unwrap();
    pvfs_client::regions::sync_generations(&mut writer, &data_dir, None).unwrap();
    let replica = Engine::open(&data_dir).unwrap();
    assert_eq!(
        replica.region_of(&wanderer).unwrap(),
        fx.photos,
        "the paired move reproduces on a replica from shipped logs"
    );
    assert_eq!(
        replica.region_of(&cargo).unwrap(),
        fx.photos,
        "descendants converge in the destination-first replay order too"
    );
    assert_eq!(
        replica.region_of(&fx.photos_child).unwrap(),
        replica.identity.root_node_id
    );
    replica.close().unwrap();
}

#[test]
fn top_logwait_wakes_on_region_commits() {
    let fx = fixture();
    let mut waiter = admin_client(&fx);
    let top_tip = waiter.log_info("").unwrap();

    // wait for top rows that will never come; a region commit must wake us
    let handle = std::thread::spawn(move || {
        let t0 = std::time::Instant::now();
        let r = waiter.log_wait(top_tip + 1, 64, 30_000, "");
        (t0.elapsed(), r)
    });
    std::thread::sleep(std::time::Duration::from_millis(600));
    // author a region event through the wire (the daemon owns the engine)
    let mut writer = admin_client(&fx);
    let k = fx.rep_key.clone();
    writer
        .mkdir(&fx.photos, "wake", move |d| {
            crypto::sign_digest(&k, d).unwrap()
        })
        .unwrap();

    let (elapsed, result) = handle.join().unwrap();
    let (_tip, events) = result.unwrap();
    assert!(events.is_empty(), "a region wake carries no top rows");
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "the wait must wake on region activity, not run out the clock ({elapsed:?})"
    );
}
