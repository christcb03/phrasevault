//! End-to-end: a real `pvfsd` over a Unix socket, exercised by `pvfs-client`,
//! with per-node ACL enforcement (doc 07 §2/§4).

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_FOLDER};
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
