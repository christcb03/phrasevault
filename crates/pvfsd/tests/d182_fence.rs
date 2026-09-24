//! PVOS D182 — an owner that knows when it is stale.
//!
//! A follower only ever copies the owner, so a follower that holds MORE of the
//! log than the owner proves the owner stale: restored from an older copy, or
//! replaced by a promotion. Such an owner fences itself and writes nothing.
//! These tests walk each row of the rule (D182 §3.3) through the real daemon.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use pvfs_client::follow::FollowEvent;
use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::fence::TipVerdict;
use pvfs_core::{crypto, identity, Engine, NodeSpec, ReplicaSource, TYPE_FOLDER};
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

fn server_msg<T: std::fmt::Debug>(r: Result<T, ClientError>) -> (String, String) {
    match r {
        Err(ClientError::Server { code, message }) => (code, message),
        other => panic!("expected a server refusal, got {other:?}"),
    }
}

fn serve_on(daemon: Arc<Daemon>) -> (tempfile::TempDir, PathBuf) {
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });
    (sockdir, sock)
}

/// An owner forest with one rwa member, served; returns the member's client.
struct Owner {
    _dir: tempfile::TempDir,
    data: PathBuf,
    root: String,
    _sockdir: tempfile::TempDir,
    key: identity::SigningKey,
    client: Client,
}

fn owner_with_member() -> Owner {
    let dir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let data = owner.data_dir().to_path_buf();
    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let public = crypto::pubkey_bytes(&key);
    owner.authorize_member(&mn, &public).unwrap();
    owner.set_acl(&root, &Principal::Key(public.clone()), acl::ACL_RWA).unwrap();
    let daemon = Arc::new(Daemon::new(owner));
    let (sockdir, sock) = serve_on(daemon);
    let k2 = key.clone();
    let client = Client::connect_signed(&sock, &public, move |d| crypto::sign_digest(&k2, d).unwrap()).unwrap();
    Owner { _dir: dir, data, root, _sockdir: sockdir, key, client }
}

#[test]
fn a_stale_owner_fences_itself_at_the_first_write_from_a_box_ahead_of_it() {
    let mut o = owner_with_member();
    let (tip, _) = pvfs_core::mount::peek_tip(&o.data).unwrap();
    let key = o.key.clone();

    // The writer's own log is five events past the owner's: a promotion
    // happened elsewhere, or this owner was restored from an older copy.
    o.client.set_write_tip(Some((tip + 5, vec![0xab; 32])));
    let (code, message) = server_msg(o.client.mkdir(&o.root, "after-the-move", |d| crypto::sign_digest(&key, d).unwrap()));
    assert_eq!(code, "forbidden");
    assert!(message.contains("fenced"), "{message}");
    let f = pvfs_core::fence::load(&o.data).expect("the owner fenced itself");
    assert_eq!((f.peer_seq, f.own_seq), (tip + 5, tip));
    assert_eq!(pvfs_core::mount::peek_tip(&o.data).unwrap().0, tip, "nothing was appended");

    // Fenced, it refuses every write — even one whose tip agrees with it.
    let (_, own_hash) = pvfs_core::mount::peek_tip(&o.data).unwrap();
    o.client.set_write_tip(Some((tip, own_hash.clone())));
    let (_, message) = server_msg(o.client.mkdir(&o.root, "still-fenced", |d| crypto::sign_digest(&key, d).unwrap()));
    assert!(message.contains("fenced"), "{message}");
    // And from a writer that sends no tip at all (an older replica).
    o.client.set_write_tip(None);
    assert_eq!(server_msg(o.client.mkdir(&o.root, "old-replica", |d| crypto::sign_digest(&key, d).unwrap())).0, "forbidden");

    // serve status says so (the page and the health record read this).
    let st = o.client.serve_status_full().unwrap();
    assert_eq!(st.log.as_ref().map(|t| t.seq), Some(tip));
    assert_eq!(st.fenced.as_ref().map(|f| f.peer_seq), Some(tip + 5));

    // A person lifts it; the owner writes again.
    assert!(pvfs_core::fence::clear(&o.data).unwrap().is_some());
    o.client.set_write_tip(Some((tip, own_hash)));
    o.client.mkdir(&o.root, "lifted", |d| crypto::sign_digest(&key, d).unwrap()).unwrap();
    assert!(pvfs_core::mount::peek_tip(&o.data).unwrap().0 > tip);
    assert!(o.client.serve_status_full().unwrap().fenced.is_none());
}

#[test]
fn a_follower_on_another_branch_is_refused_and_the_owner_keeps_writing() {
    let mut o = owner_with_member();
    let key = o.key.clone();
    // Seq 1 is genesis: any other hash there is another branch.
    o.client.set_write_tip(Some((1, vec![0x5a; 32])));
    let (code, message) = server_msg(o.client.mkdir(&o.root, "from-a-ghost", |d| crypto::sign_digest(&key, d).unwrap()));
    assert_eq!(code, "forbidden");
    assert!(message.contains("differs"), "{message}");
    assert!(pvfs_core::fence::load(&o.data).is_none(), "one bad follower must not stop the forest");

    // The same writer, on the owner's chain (behind it): accepted.
    let c = rusqlite::Connection::open_with_flags(o.data.join("log.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let genesis: Vec<u8> = c.query_row("SELECT chain_hash FROM events WHERE seq = 1", [], |r| r.get(0)).unwrap();
    o.client.set_write_tip(Some((1, genesis)));
    o.client.mkdir(&o.root, "lagging-but-true", |d| crypto::sign_digest(&key, d).unwrap()).unwrap();
}

#[test]
fn a_fenced_owner_opens_and_refuses_every_append_until_the_fence_is_lifted() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let data = engine.data_dir().to_path_buf();
    let root = engine.identity.root_node_id.clone();
    engine.close().unwrap();

    let (tip, _) = pvfs_core::mount::peek_tip(&data).unwrap();
    let (v, own) = pvfs_core::fence::check_peer(&data, "192.168.1.142:7435", tip + 3, &[1u8; 32]).unwrap();
    assert_eq!((v, own), (TipVerdict::Ahead, tip));
    let f = pvfs_core::fence::load(&data).expect("the health rule fences an owner");
    assert!(f.reason.contains("192.168.1.142:7435"), "{}", f.reason);

    // It still opens (to serve reads and say why), and appends nothing.
    let mut engine = Engine::open(&data).unwrap();
    match engine.add_node(&root, folder("x")) {
        Err(pvfs_core::PvfsError::Forbidden { reason, .. }) => assert!(reason.contains("fenced"), "{reason}"),
        other => panic!("expected the fence, got {other:?}"),
    }
    engine.close().unwrap();
    assert_eq!(pvfs_core::mount::peek_tip(&data).unwrap().0, tip);

    pvfs_core::fence::clear(&data).unwrap();
    let mut engine = Engine::open(&data).unwrap();
    engine.add_node(&root, folder("x")).unwrap();
    engine.close().unwrap();
}

#[test]
fn the_health_rule_never_fences_a_replica() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let data = engine.data_dir().to_path_buf();
    engine.close().unwrap();
    // A replica marker: this data dir only follows; its peers are not evidence.
    ReplicaSource { transport: "socket".into(), target: "/nonexistent".into(), pin: String::new(), region: String::new() }
        .save(&data)
        .unwrap();
    let (tip, _) = pvfs_core::mount::peek_tip(&data).unwrap();
    let (v, _) = pvfs_core::fence::check_peer(&data, "peer", tip + 1, &[2u8; 32]).unwrap();
    assert_eq!(v, TipVerdict::Ahead);
    assert!(pvfs_core::fence::load(&data).is_none());
}

/// One process-wide config dir: the follower dials with the client identity,
/// resolved through env (see serve_jobs.rs for why it is made inside the once).
fn test_config_dir() -> &'static Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let d = DIR.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", d.path());
        identity::client_identity_mnemonic().unwrap();
        d
    });
    d.path()
}

fn copy_file(from: &Path, to: &Path) {
    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
    std::fs::copy(from, to).unwrap();
}

#[test]
fn a_follower_says_when_its_source_is_behind_it() {
    test_config_dir();
    let cmn = identity::client_identity_mnemonic().unwrap();
    let ckey = identity::device_key(&cmn, "", 0).unwrap();
    let cpub = crypto::pubkey_bytes(&ckey);

    // The owner, with the follower's identity allowed to replicate.
    let odir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(odir.path()).unwrap();
    let data = owner.data_dir().to_path_buf();
    let root = owner.identity.root_node_id.clone();
    owner.authorize_member(&mn, &cpub).unwrap();
    owner.set_acl(&root, &Principal::Key(cpub.clone()), acl::ACL_RWA).unwrap();
    owner.shutdown_checkpoint().unwrap();
    owner.close().unwrap();

    // An OLD copy of the owner (what a restored image would be) …
    let old = tempfile::tempdir().unwrap();
    let old_data = old.path().join(".pvfs");
    for f in ["log.db", "index.db", "device.key"] {
        copy_file(&data.join(f), &old_data.join(f));
    }
    // … while the real owner moves on, and a replica copies it.
    let mut owner = Engine::open(&data).unwrap();
    owner.add_node(&root, folder("later-1")).unwrap();
    owner.add_node(&root, folder("later-2")).unwrap();
    owner.shutdown_checkpoint().unwrap();
    owner.close().unwrap();
    let rdir = tempfile::tempdir().unwrap();
    let rdata = rdir.path().join(".pvfs");
    copy_file(&data.join("log.db"), &rdata.join("log.db"));

    // The replica is pointed at the old copy — the stale owner.
    let stale = Arc::new(Daemon::new(Engine::open(&old_data).unwrap()));
    let (_sd, sock) = serve_on(stale);
    ReplicaSource { transport: "socket".into(), target: sock.to_string_lossy().into_owned(), pin: String::new(), region: String::new() }
        .save(&rdata)
        .unwrap();

    let reasons = Arc::new(Mutex::new(Vec::<String>::new()));
    let ups = Arc::new(Mutex::new(0u32));
    let stop: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let t = {
        let (reasons, ups, rdata) = (Arc::clone(&reasons), Arc::clone(&ups), rdata.clone());
        std::thread::spawn(move || {
            pvfs_client::follow::run(&rdata, 200, stop, |ev| match ev {
                FollowEvent::Retrying { reason } => reasons.lock().unwrap().push(reason),
                FollowEvent::UpToDate { .. } => *ups.lock().unwrap() += 1,
                _ => {}
            })
        })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline
        && !reasons.lock().unwrap().iter().any(|r| r.contains("is behind this replica"))
    {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = t.join();
    let said = reasons.lock().unwrap().clone();
    assert!(
        said.iter().any(|r| r.contains("is behind this replica")),
        "the follower must say its source is behind it; it said {said:?}"
    );
    assert_eq!(*ups.lock().unwrap(), 0, "a source behind this replica is never 'up to date'");
}
