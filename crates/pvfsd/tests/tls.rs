//! F1 — the network transport end-to-end (doc 17 §4): the same protocol the
//! Unix socket speaks, over TCP+TLS, verified by the transport pin.

use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_FOLDER};
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

#[test]
fn tls_serves_the_protocol_and_refuses_a_wrong_pin() {
    // ---- a forest with a public folder and a member-only folder
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let shared = engine.add_node(&root, folder("shared")).unwrap();
    let _clip = engine.add_node(&shared, folder("clip")).unwrap();
    let private = engine.add_node(&root, folder("private")).unwrap();
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();
    engine
        .set_acl(&shared, &Principal::Public, acl::ACL_R)
        .unwrap();
    engine
        .set_acl(&private, &Principal::Key(member_pub.clone()), acl::ACL_R)
        .unwrap();

    // ---- serve TCP+TLS on an ephemeral port
    let tls = nettls::load_or_generate(dir.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let daemon = Arc::new(Daemon::new(engine));
    let cfg = Arc::clone(&tls.config);
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            static NEVER: AtomicBool = AtomicBool::new(false);
            let _ = serve_tls_until(listener, cfg, d, &NEVER);
        });
    }

    // ---- pinned public client: identical protocol to the Unix socket
    let mut anon = Client::connect_tcp_public(&addr, &tls.pin).unwrap();
    assert_eq!(anon.principal, "public");
    assert_eq!(anon.info().unwrap().root, root);
    let labels: Vec<String> = anon
        .ls(&shared)
        .unwrap()
        .into_iter()
        .map(|c| c.label)
        .collect();
    assert_eq!(labels, vec!["clip"]);
    assert!(anon.ls(&private).is_err(), "no public grant on /private");

    // ---- challenge-response still gates identity over TLS
    let mut member = Client::connect_tcp_signed(&addr, &tls.pin, &member_pub, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();
    assert!(member.principal.starts_with("key:"));
    assert!(member.ls(&private).is_ok(), "member reads the key grant");

    // ---- a wrong pin never reaches the protocol
    let err = Client::connect_tcp_public(&addr, &"0".repeat(64))
        .err()
        .expect("wrong pin must fail the handshake");
    assert!(
        !matches!(err, ClientError::Server { .. }),
        "failure must be the TLS handshake, not a served error: {err}"
    );
}
