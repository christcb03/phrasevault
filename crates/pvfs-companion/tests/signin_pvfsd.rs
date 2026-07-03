//! The real `pvfsd` challenge consumer (doc 16 §6, phase 7 item 2): "Sign in
//! with PVFS" proven end to end against a live daemon.
//!
//! The loop this closes: (1) `pvfsd` issues its doc 07 §2 challenge on connect;
//! (2) the app hands the challenge digest to the companion's loopback
//! `POST /sign-in` (origin-gated); (3) the companion signs it with the
//! **identity key**; (4) the app presents `{pubkey, sig}` back to `pvfsd`,
//! which verifies it exactly like a CLI client's `Auth` — the identity key is
//! an authorized member, so ACLs apply to it like any other principal.
//!
//! This is also the reference for app authors: the signing closure below is
//! the whole client-side integration.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_companion::approve::Prompter;
use pvfs_companion::{
    Agent, ApprovalPolicy, Origin, OriginRegistry, RequestType, UnlockedSigner, WebAgent,
};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

struct ApproveAll;
impl Prompter for ApproveAll {
    fn approve(&self, _r: RequestType, _o: Origin) -> bool {
        true
    }
    fn approve_connect(&self, _origin: &str) -> bool {
        true
    }
}

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

/// Raw HTTP/1.1 request to the loopback agent: returns (status, body).
fn http(addr: &str, method: &str, path: &str, origin: &str, token: &str, body: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nOrigin: {origin}\r\n\
         X-PVFS-Token: {token}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status: u16 = resp
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
    (status, body)
}

fn jfield(body: &str, key: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    v[key].as_str().unwrap_or_default().to_string()
}

#[test]
fn sign_in_with_pvfs_against_a_live_daemon() {
    // ---- the human's companion: their phrase, identity key 3'/0'
    let mn = identity::generate_mnemonic().unwrap();
    let id_pub = crypto::pubkey_bytes(&identity::identity_key(&mn, "", 0).unwrap());

    // ---- a forest whose owner authorized that identity as a member,
    //      with r on /files and nothing on /private
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let files = engine.add_node(&root, folder("files")).unwrap();
    let _doc = engine.add_node(&files, folder("doc")).unwrap();
    let private = engine.add_node(&root, folder("private")).unwrap();
    engine.authorize_member(&owner_mn, &id_pub).unwrap();
    engine
        .set_acl(&files, &Principal::Key(id_pub.clone()), acl::ACL_R)
        .unwrap();

    // ---- step 1's server: a real pvfsd on a temp socket
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

    // ---- steps 2–3's signer: the companion's loopback identity agent
    let signer = UnlockedSigner::from_phrase(&mn.to_string()).unwrap();
    let agent =
        Arc::new(Agent::new(signer, ApprovalPolicy::default()).with_prompter(Box::new(ApproveAll)));
    let regdir = tempfile::tempdir().unwrap();
    let web = Arc::new(WebAgent::new(
        agent,
        OriginRegistry::at(&regdir.path().join("origins.json")),
    ));
    let token = web.token().to_string();
    let http_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = http_listener.local_addr().unwrap().to_string();
    {
        let w = Arc::clone(&web);
        std::thread::spawn(move || w.serve(http_listener));
    }

    // The app's origin connects once (the human approves — wallet-style).
    let app = "https://app.example";
    let (code, body) = http(&addr, "POST", "/connect", app, &token, "");
    assert_eq!(code, 200, "{body}");

    // ---- the whole app-side integration is this closure: hand the daemon's
    //      challenge digest to the companion, get the signature back.
    let mut client = Client::connect_signed(&sock, &id_pub, |digest| {
        let (code, body) = http(
            &addr,
            "POST",
            "/sign-in",
            app,
            &token,
            &format!("{{\"challenge\":\"{}\"}}", hex::encode(digest)),
        );
        assert_eq!(code, 200, "sign-in failed: {body}");
        // The companion says which key signed — it must be the member key
        // the daemon is about to check.
        assert_eq!(jfield(&body, "pubkey"), hex::encode(&id_pub));
        hex::decode(jfield(&body, "sig")).unwrap()
    })
    .unwrap();

    // ---- step 4 verified: the daemon authenticated the identity key as a
    //      member principal, and ACLs bind to it.
    assert_eq!(client.principal, format!("key:{}", hex::encode(&id_pub)));
    let labels: Vec<String> = client
        .ls(&files)
        .unwrap()
        .iter()
        .map(|c| c.label.clone())
        .collect();
    assert_eq!(labels, vec!["doc"]); // the key grant admits the signed-in user
    assert!(
        matches!(client.ls(&private), Err(ClientError::Server { code, .. }) if code == "forbidden"),
        "no grant on /private — the signed-in principal is scoped by ACLs"
    );
}
