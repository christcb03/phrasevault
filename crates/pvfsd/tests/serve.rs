//! End-to-end: a real `pvfsd` over a Unix socket, exercised by `pvfs-client`,
//! with per-node ACL enforcement (doc 07 §2/§4).

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{
    crypto, identity, Engine, FilePayload, NodeSpec, TYPE_FILE, TYPE_FOLDER, TYPE_SECURE,
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

fn secure(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_SECURE.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

/// Doc 12 §8.5 daemon path: a member with `w` updates a secure blob over the
/// socket (ciphertext upload + member-signed ledger), reads it back verified,
/// and a member WITHOUT write is refused. The daemon only ever sees ciphertext.
#[test]
fn daemon_secure_put_and_cat_multi_user() {
    let dir = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let blob = engine.add_node(&root, secure("shared.enc")).unwrap();
    let uri = pvfs_core::storage::path_to_uri(&store.path().join("shared.enc")).unwrap();
    engine.add_location(&blob, &uri).unwrap();

    // Two members: writer (w on the blob) and reader (r only).
    let writer_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let writer = crypto::pubkey_bytes(&writer_key);
    let reader_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let reader = crypto::pubkey_bytes(&reader_key);
    engine.authorize_member(&owner_mn, &writer).unwrap();
    engine.authorize_member(&owner_mn, &reader).unwrap();
    engine.set_acl(&blob, &Principal::Key(writer.clone()), acl::ACL_R | acl::ACL_W).unwrap();
    engine.set_acl(&blob, &Principal::Key(reader.clone()), acl::ACL_R).unwrap();

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

    // The writer uploads ciphertext and commits the ledger over the socket.
    let ciphertext = b"opaque encrypted bytes v1";
    let mut w = Client::connect_signed(&sock, &writer, |d| crypto::sign_digest(&writer_key, d).unwrap())
        .unwrap();
    w.secure_put(&blob, ciphertext, |d| crypto::sign_digest(&writer_key, d).unwrap())
        .unwrap();
    // The daemon wrote exactly those bytes to the location — nothing decrypted.
    assert_eq!(std::fs::read(store.path().join("shared.enc")).unwrap(), ciphertext);

    // The reader downloads the verified ciphertext.
    let mut r = Client::connect_signed(&sock, &reader, |d| crypto::sign_digest(&reader_key, d).unwrap())
        .unwrap();
    assert_eq!(r.secure_cat(&blob).unwrap(), ciphertext);

    // The reader (no w) cannot update the blob.
    assert!(forbidden(
        r.secure_put(&blob, b"forged", |d| crypto::sign_digest(&reader_key, d).unwrap())
    ));
    // The writer can overwrite; the reader sees the new bytes.
    w.secure_put(&blob, b"v2 bytes", |d| crypto::sign_digest(&writer_key, d).unwrap())
        .unwrap();
    assert_eq!(r.secure_cat(&blob).unwrap(), b"v2 bytes");
}

/// Doc 12 §8.5: an app (or member) **creates** a secure store on the fly over
/// the daemon — no path, no stopping the filesystem — then writes and reads it.
/// This is the messenger "new chat = new encrypted store" case.
#[test]
fn daemon_creates_secure_store_on_the_fly() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    // The owner's admin device (authorized at init) is our authenticated client.
    let dev = identity::device_key(&owner_mn, "", 0).unwrap();
    let dev_pub = crypto::pubkey_bytes(&dev);

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

    let mut c = Client::connect_signed(&sock, &dev_pub, |d| crypto::sign_digest(&dev, d).unwrap())
        .unwrap();
    // Create the store — daemon stays up the whole time.
    let blob = c
        .secure_create(&root, "chat-42", |d| crypto::sign_digest(&dev, d).unwrap())
        .unwrap();
    // Write to it immediately; the managed location is allocated on this first put.
    c.secure_put(&blob, b"first message ciphertext", |d| crypto::sign_digest(&dev, d).unwrap())
        .unwrap();
    assert_eq!(c.secure_cat(&blob).unwrap(), b"first message ciphertext");
    // And a second store, still live.
    let blob2 = c
        .secure_create(&root, "chat-43", |d| crypto::sign_digest(&dev, d).unwrap())
        .unwrap();
    assert_ne!(blob, blob2);
    c.secure_put(&blob2, b"other chat", |d| crypto::sign_digest(&dev, d).unwrap())
        .unwrap();
    assert_eq!(c.secure_cat(&blob2).unwrap(), b"other chat");
}

// AddNode/Payload (doc 13: log-resident records, e.g. PVOS grant events):
// member-signed typed node with inline payload, read back ACL-gated.
#[test]
fn daemon_add_node_payload_roundtrip_and_guards() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let region = engine.add_node(&root, folder("region")).unwrap();

    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();
    engine
        .set_acl(
            &region,
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

    let sign = |d: &[u8; 32]| crypto::sign_digest(&member_key, d).unwrap();
    let mut member = Client::connect_signed(&sock, &member_pub, sign).unwrap();

    // round-trip: typed node, payload back intact, visible in ls with its type
    let rec = br#"{"type":"grant","id":"g-1"}"#;
    let id = member
        .add_node(&region, "g-1", "pvos.grant", rec, sign)
        .unwrap();
    assert_eq!(member.payload(&id).unwrap(), rec.to_vec());
    let kid = member
        .ls(&region)
        .unwrap()
        .into_iter()
        .find(|c| c.id == id)
        .expect("new node listed");
    assert_eq!(kid.node_type, "pvos.grant");

    // guards: reserved types refused; oversize payload refused; no write ACL → forbidden
    assert!(member
        .add_node(&region, "x", TYPE_FOLDER, b"", sign)
        .is_err());
    assert!(member
        .add_node(&region, "x", TYPE_SECURE, b"", sign)
        .is_err());
    let big = vec![0u8; 64 * 1024 + 1];
    assert!(member
        .add_node(&region, "big", "pvos.grant", &big, sign)
        .is_err());
    assert!(forbidden(member.add_node(
        &root,
        "sneaky",
        "pvos.grant",
        rec,
        sign
    )));

    // payload read is ACL-gated: an anonymous client can't read it
    let mut anon = Client::connect_public(&sock).unwrap();
    assert!(forbidden(anon.payload(&id)));
}
