//! End-to-end: a real `pvfsd` over a Unix socket, exercised by `pvfs-client`,
//! with per-node ACL enforcement (doc 07 §2/§4).

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine, FilePayload, NodeSpec, TYPE_FILE, TYPE_FOLDER};
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

fn labels(kids: &[pvfs_client::ChildInfo]) -> Vec<String> {
    kids.iter().map(|c| c.label.clone()).collect()
}

#[test]
fn daemon_serves_reads_with_acl_enforcement() {
    // ---- build a forest: root/{shared(public r)/clip, private(member r)/secret}
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let shared = engine.add_node(&root, folder("shared")).unwrap();
    let _clip = engine.add_node(&shared, folder("clip")).unwrap();
    let private = engine.add_node(&root, folder("private")).unwrap();
    let _secret = engine.add_node(&private, folder("secret")).unwrap();

    // a member key (the client will prove possession of it)
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();

    engine
        .set_acl(&shared, &Principal::Public, acl::ACL_R)
        .unwrap(); // anyone may read /shared
    engine
        .set_acl(&private, &Principal::Key(member_pub.clone()), acl::ACL_R)
        .unwrap(); // only the member may read /private

    // ---- start the daemon on a temp socket
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

    // ---- public (unauthenticated) client
    let mut anon = Client::connect_public(&sock).unwrap();
    assert_eq!(anon.principal, "public");
    assert_eq!(anon.info().unwrap().root, root);
    assert_eq!(labels(&anon.ls(&shared).unwrap()), vec!["clip"]); // public grant
    assert!(forbidden(anon.ls(&private))); // not public
    assert!(forbidden(anon.ls(&root))); // root has no grant

    // ---- member client (proves the key by signing the challenge)
    let mut member = Client::connect_signed(&sock, &member_pub, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();
    assert!(member.principal.starts_with("key:"));
    assert_eq!(labels(&member.ls(&private).unwrap()), vec!["secret"]); // key grant
    assert!(member.ls(&shared).is_ok()); // public applies to members too
}

fn forbidden<T>(r: Result<T, ClientError>) -> bool {
    matches!(r, Err(ClientError::Server { code, .. }) if code == "forbidden")
}

// doc 08 §4 item 4 — graceful shutdown: the accept loop serves normally, then
// returns once the shutdown flag is set, and the engine can be checkpointed.
#[test]
fn serve_until_stops_on_shutdown_flag() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let daemon = Arc::new(Daemon::new(engine));

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();

    let shutdown = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&shutdown);
    let d = Arc::clone(&daemon);
    let handle = std::thread::spawn(move || pvfsd::serve_until(listener, d, &s).unwrap());

    // the daemon serves normally while the loop runs
    let mut anon = Client::connect_public(&sock).unwrap();
    assert_eq!(anon.info().unwrap().root, root);

    // request shutdown — the loop must observe the flag and return promptly
    shutdown.store(true, Ordering::SeqCst);
    handle.join().unwrap();

    // and the clean-shutdown checkpoint is callable afterward
    daemon.shutdown_checkpoint().unwrap();
}

// doc 07 §5 — a member creates a folder through the daemon (two-phase, signed)
#[test]
fn daemon_member_write() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let dropbox = engine.add_node(&root, folder("dropbox")).unwrap();

    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();
    engine
        .set_acl(
            &dropbox,
            &Principal::Key(member_pub.clone()),
            acl::ACL_R | acl::ACL_W,
        )
        .unwrap();

    let daemon = Arc::new(Daemon::new(engine));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }

    let mut member = Client::connect_signed(&sock, &member_pub, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();

    // create a folder under dropbox (member has write there)
    let new_id = member
        .mkdir(&dropbox, "uploads", |d| {
            crypto::sign_digest(&member_key, d).unwrap()
        })
        .unwrap();
    assert_eq!(member.stat(&new_id).unwrap().label, "uploads");
    assert!(labels(&member.ls(&dropbox).unwrap()).contains(&"uploads".to_string()));

    // but not under root (no write there)
    assert!(forbidden(member.mkdir(&root, "nope", |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })));
}

// doc 07 §5 — a member adds a file then removes it through the daemon
#[test]
fn daemon_member_add_file_and_rm() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let dropbox = engine.add_node(&root, folder("dropbox")).unwrap();
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();
    engine
        .set_acl(
            &dropbox,
            &Principal::Key(member_pub.clone()),
            acl::ACL_R | acl::ACL_W,
        )
        .unwrap();

    let daemon = Arc::new(Daemon::new(engine));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let mut m = Client::connect_signed(&sock, &member_pub, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();

    let file_id = m
        .add_file(&dropbox, "clip.mkv", 1234, "video/x-matroska", |d| {
            crypto::sign_digest(&member_key, d).unwrap()
        })
        .unwrap();
    assert_eq!(m.stat(&file_id).unwrap().node_type, "file");
    assert!(labels(&m.ls(&dropbox).unwrap()).contains(&"clip.mkv".to_string()));

    m.rm(&file_id, |d| crypto::sign_digest(&member_key, d).unwrap())
        .unwrap();
    assert!(!labels(&m.ls(&dropbox).unwrap()).contains(&"clip.mkv".to_string()));
}

// doc 07 §6 — read a file's bytes over the daemon, ACL-checked
#[test]
fn daemon_cat_reads_file_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    // a real file on disk + a file node that points at it
    let file_path = dir.path().join("hello.txt");
    std::fs::write(&file_path, b"hello pvfs").unwrap();
    let file_node = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "hello.txt".into(),
                payload: FilePayload {
                    content_hash: String::new(),
                    size_bytes: 10,
                    mime_type: "text/plain".into(),
                    original_name: "hello.txt".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine
        .add_location(&file_node, &format!("file://{}", file_path.display()))
        .unwrap();

    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();
    engine
        .set_acl(&root, &Principal::Key(member_pub.clone()), acl::ACL_R)
        .unwrap();

    let daemon = Arc::new(Daemon::new(engine));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }

    // the member can read the bytes
    let mut member = Client::connect_signed(&sock, &member_pub, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();
    let mut buf = Vec::new();
    member.cat(&file_node, &mut buf).unwrap();
    assert_eq!(buf, b"hello pvfs");

    // an anonymous client (no public grant) is refused
    let mut anon = Client::connect_public(&sock).unwrap();
    let mut empty = Vec::new();
    assert!(forbidden(anon.cat(&file_node, &mut empty)));
}

// doc 09 §3c — live admin through the socket: the owner authorizes a member and
// grants access over the daemon, and the member can immediately write (no restart)
#[test]
fn daemon_live_admin_through_socket() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let owner_key = identity::device_key(&owner_mn, "", 0).unwrap(); // device 0 = admin
    let owner_pub = crypto::pubkey_bytes(&owner_key);
    assert_eq!(owner_pub, engine.device_pubkey());

    let daemon = Arc::new(Daemon::new(engine));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }

    // a brand-new member identity, not yet known to the forest
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    let member_hex = hex::encode(&member_pub);

    // OWNER connects (admin) and live-admins entirely over the socket
    let mut owner = Client::connect_signed(&sock, &owner_pub, |d| {
        crypto::sign_digest(&owner_key, d).unwrap()
    })
    .unwrap();
    owner
        .authorize_member(&member_hex, |d| crypto::sign_digest(&owner_key, d).unwrap())
        .unwrap();
    owner
        .set_acl(&root, &format!("key:{member_hex}"), "rw", |d| {
            crypto::sign_digest(&owner_key, d).unwrap()
        })
        .unwrap();

    // the MEMBER connects and writes immediately — the changes took effect live
    let mut member = Client::connect_signed(&sock, &member_pub, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();
    member
        .mkdir(&root, "by-member", |d| {
            crypto::sign_digest(&member_key, d).unwrap()
        })
        .unwrap();
    assert!(labels(&member.ls(&root).unwrap()).contains(&"by-member".to_string()));
}

// doc 09 §4 — a member moves a node between folders through the daemon
#[test]
fn daemon_member_move() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let a = engine.add_node(&root, folder("a")).unwrap();
    let b = engine.add_node(&root, folder("b")).unwrap();
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();
    engine
        .set_acl(&root, &Principal::Key(member_pub.clone()), acl::ACL_R | acl::ACL_W)
        .unwrap();

    let daemon = Arc::new(Daemon::new(engine));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let mut m = Client::connect_signed(&sock, &member_pub, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();

    let node = m
        .mkdir(&a, "item", |d| crypto::sign_digest(&member_key, d).unwrap())
        .unwrap();
    assert!(labels(&m.ls(&a).unwrap()).contains(&"item".to_string()));

    m.mv(&node, &b, |d| crypto::sign_digest(&member_key, d).unwrap())
        .unwrap();
    assert!(!labels(&m.ls(&a).unwrap()).contains(&"item".to_string()));
    assert!(labels(&m.ls(&b).unwrap()).contains(&"item".to_string()));
}

// doc 08 RtO #4 — multi-user isolation: an authorized member with rw can write,
// but **cannot** perform admin (grant ACLs / authorize members) over the socket.
#[test]
fn daemon_member_cannot_admin() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let dropbox = engine.add_node(&root, folder("dropbox")).unwrap();
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();
    engine
        .set_acl(&dropbox, &Principal::Key(member_pub.clone()), acl::ACL_R | acl::ACL_W)
        .unwrap();

    let daemon = Arc::new(Daemon::new(engine));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }

    let mut member = Client::connect_signed(&sock, &member_pub, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();

    // the member can write where granted (sanity)
    assert!(member
        .mkdir(&dropbox, "ok", |d| crypto::sign_digest(&member_key, d).unwrap())
        .is_ok());
    // but rw is not admin: granting an ACL must be forbidden
    assert!(
        forbidden(member.set_acl(&dropbox, "public", "r", |d| {
            crypto::sign_digest(&member_key, d).unwrap()
        })),
        "a non-admin member must not set ACLs over the socket"
    );
    // and authorizing a new member must be forbidden too
    let other = crypto::pubkey_bytes(
        &identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap(),
    );
    assert!(
        forbidden(member.authorize_member(&hex::encode(&other), |d| {
            crypto::sign_digest(&member_key, d).unwrap()
        })),
        "a non-admin member must not authorize members over the socket"
    );
}
