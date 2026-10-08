//! PVOS D222b — refusals and changes of authority are logged, with who
//! asked and from where: a denied op, a refused handshake, a TLS handshake
//! that fails, a revoked key used, and the authority a commit changed.
//! The daemon runs on other threads, so the records are read with
//! `pvfs_log::testing::GlobalCapture`.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pvfs_client::Client;
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_FOLDER};
use pvfs_log::testing::GlobalCapture;
use pvfs_log::{Category, Outcome, Record, Value};
use pvfsd::{nettls, serve_tls_until, Daemon};

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

fn field<'a>(r: &'a Record, name: &str) -> Option<&'a Value> {
    r.fields.iter().find(|f| f.name == name).map(|f| &f.value)
}

fn s(v: Option<&Value>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

/// Wait up to 5 s for `want` records of `event` that `pick` accepts.
fn wait_for(cap: &GlobalCapture, event: &str, want: usize, pick: impl Fn(&Record) -> bool) -> Vec<Record> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let got: Vec<Record> = cap.events(event).into_iter().filter(|r| pick(r)).collect();
        if got.len() >= want || Instant::now() > deadline {
            return got;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn refusals_and_authority_changes_are_logged_with_who_and_where() {
    let cap = GlobalCapture::start();

    // ---- a forest with a member-only folder, served over TCP+TLS
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let private = engine.add_node(&root, folder("private")).unwrap();
    let owner_key = identity::device_key(&owner_mn, "", 0).unwrap();
    let owner_pub = crypto::pubkey_bytes(&owner_key);
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    let member_hex = hex::encode(&member_pub);
    engine.set_acl(&private, &Principal::Key(member_pub.clone()), acl::ACL_R).unwrap();

    let tls = nettls::load_or_generate(dir.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let daemon = Arc::new(Daemon::new(engine));
    {
        let d = Arc::clone(&daemon);
        let cfg = Arc::clone(&tls.config);
        std::thread::spawn(move || {
            static NEVER: AtomicBool = AtomicBool::new(false);
            let _ = serve_tls_until(listener, cfg, d, &NEVER);
        });
    }

    // ---- 1. a denied op: who (public), from where (this TCP peer), what
    let mut anon = Client::connect_tcp_public(&addr, &tls.pin).unwrap();
    assert!(anon.ls(&private).is_err(), "no public grant on /private");
    let denied = wait_for(&cap, "pvfs.access.denied", 1, |r| s(field(r, "principal")) == "public");
    assert_eq!(denied.len(), 1, "one denial for the public ls: {denied:?}");
    let d = &denied[0];
    assert_eq!(d.category, Category::Security);
    assert_eq!(d.outcome, Some(Outcome::Failure));
    assert_eq!(s(field(d, "op")), "ls");
    assert!(s(field(d, "peer_addr")).starts_with("127.0.0.1:"), "{d:?}");
    assert!(d.line().starts_with("pvfsd: ls refused for public from 127.0.0.1:"), "{}", d.line());
    // At `minimal` the address stays (a security event), the reason goes.
    let v = pvfs_log::render(d, pvfs_log::Privacy::Minimal, None);
    assert!(v.line().contains("127.0.0.1:"), "{}", v.line());
    assert!(v.fields.iter().all(|f| f.name != "reason"));

    // ---- 2. a refused handshake: a signature that does not verify
    let bad = Client::connect_tcp_signed(&addr, &tls.pin, &member_pub, |_d| vec![0u8; 64]);
    assert!(bad.is_err(), "a bad signature must not authenticate");
    let refused = wait_for(&cap, "pvfs.auth.refused", 1, |r| s(field(r, "reason")) == "bad_signature");
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(s(field(&refused[0], "principal")), format!("key:{member_hex}"));
    assert!(s(field(&refused[0], "peer_addr")).starts_with("127.0.0.1:"));

    // ---- 3. a TLS handshake that fails is logged; one that is left is not
    drop(TcpStream::connect(&addr).unwrap()); // a port check
    std::thread::sleep(Duration::from_millis(300));
    let mut junk = TcpStream::connect(&addr).unwrap();
    junk.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let tls_failed = wait_for(&cap, "pvfs.tls.handshake_failed", 1, |_| true);
    std::thread::sleep(Duration::from_millis(300));
    let tls_failed_all = cap.events("pvfs.tls.handshake_failed");
    assert_eq!(tls_failed.len(), 1, "the junk handshake: {tls_failed:?}");
    assert_eq!(tls_failed_all.len(), 1, "the port check is not logged: {tls_failed_all:?}");
    drop(junk);

    // ---- 4. authority changes, logged once with author and subject
    let mut owner = Client::connect_tcp_signed(&addr, &tls.pin, &owner_pub, |d| {
        crypto::sign_digest(&owner_key, d).unwrap()
    })
    .unwrap();
    owner.authorize_member(&member_hex, |d| crypto::sign_digest(&owner_key, d).unwrap()).unwrap();
    owner
        .set_acl(&root, &format!("key:{member_hex}"), "rw", |d| crypto::sign_digest(&owner_key, d).unwrap())
        .unwrap();
    let authorized = wait_for(&cap, "pvfs.authority.device_authorized", 1, |r| {
        s(field(r, "device")) == format!("key:{member_hex}")
    });
    assert_eq!(authorized.len(), 1, "{authorized:?}");
    assert_eq!(authorized[0].category, Category::Audit);
    assert_eq!(s(field(&authorized[0], "author")), format!("key:{}", hex::encode(&owner_pub)));
    assert!(matches!(field(&authorized[0], "seq"), Some(Value::UInt(n)) if *n > 0));
    let acl_set = wait_for(&cap, "pvfs.authority.acl_set", 1, |r| s(field(r, "grantee")) == format!("key:{member_hex}"));
    assert_eq!(acl_set.len(), 1, "{acl_set:?}");
    assert_eq!(s(field(&acl_set[0], "node")), root);

    // ---- 5. a revoked key used: the member writes, is revoked, tries again
    let mut member = Client::connect_tcp_signed(&addr, &tls.pin, &member_pub, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();
    member.mkdir(&root, "before", |d| crypto::sign_digest(&member_key, d).unwrap()).unwrap();
    owner.revoke(&member_hex, |d| crypto::sign_digest(&owner_key, d).unwrap()).unwrap();
    let revoked = wait_for(&cap, "pvfs.authority.device_revoked", 1, |r| {
        s(field(r, "device")) == format!("key:{member_hex}")
    });
    assert_eq!(revoked.len(), 1, "{revoked:?}");
    assert!(member.mkdir(&root, "after", |d| crypto::sign_digest(&member_key, d).unwrap()).is_err());
    let used = wait_for(&cap, "pvfs.access.revoked_key", 1, |r| {
        s(field(r, "principal")) == format!("key:{member_hex}")
    });
    assert_eq!(used.len(), 1, "a revoked key's write: {used:?}");
    assert_eq!(used[0].category, Category::Security);
}

#[test]
fn a_flood_of_bad_handshakes_is_rate_limited() {
    let cap = GlobalCapture::start();
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let tls = nettls::load_or_generate(dir.path()).unwrap();
    // A second loopback address, so the other test's refusals (127.0.0.1)
    // never share this one's limit.
    let listener = TcpListener::bind("127.0.0.2:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let daemon = Arc::new(Daemon::new(engine));
    {
        let d = Arc::clone(&daemon);
        let cfg = Arc::clone(&tls.config);
        std::thread::spawn(move || {
            static NEVER: AtomicBool = AtomicBool::new(false);
            let _ = serve_tls_until(listener, cfg, d, &NEVER);
        });
    }
    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let pubk = crypto::pubkey_bytes(&key);
    for _ in 0..30 {
        let _ = Client::connect_tcp_signed(&addr, &tls.pin, &pubk, |_d| vec![1u8; 64]);
    }
    let mine = |r: &Record| s(field(r, "principal")) == format!("key:{}", hex::encode(&pubk));
    let _ = wait_for(&cap, "pvfs.auth.refused", 10, mine);
    std::thread::sleep(Duration::from_millis(500));
    let got: Vec<Record> = cap.events("pvfs.auth.refused").into_iter().filter(mine).collect();
    assert_eq!(got.len(), 10, "ten a minute from one address, the rest counted: {}", got.len());
}
