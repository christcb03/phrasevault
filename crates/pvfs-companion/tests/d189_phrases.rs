//! PVOS D189 — two recovery phrases served by one companion, over its socket.
//!
//! A request that names a public key goes to the phrase holding it; one that
//! names none goes to the default phrase (every client before protocol v4);
//! `list_keys` lists both; a key no phrase holds is refused.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_companion::router::Slot;
use pvfs_companion::{
    request, request_for_key, serve_router, Agent, AgentRequest, AgentResponse, ApprovalPolicy, Router,
    UnlockedSigner,
};
use pvfs_core::{crypto, identity};

fn phrase() -> String {
    identity::generate_mnemonic().unwrap().to_string()
}

fn root_of(phrase: &str) -> Vec<u8> {
    let mn = identity::parse_mnemonic(phrase).unwrap();
    crypto::pubkey_bytes(&identity::root_key(&mn, "").unwrap())
}

fn agent(phrase: &str) -> Arc<Agent> {
    let policy = ApprovalPolicy { auto_root: true, ..Default::default() };
    Arc::new(Agent::new(UnlockedSigner::from_phrase(phrase).unwrap(), policy))
}

fn root_pubkey(r: AgentResponse) -> Vec<u8> {
    match r {
        AgentResponse::Pubkey { pubkey } => hex::decode(pubkey).unwrap(),
        other => panic!("expected a pubkey, got {other:?}"),
    }
}

#[test]
fn one_companion_serves_two_phrases_by_key() {
    let (main, media2) = (phrase(), phrase());
    let router = Router::new(vec![
        Slot::new("companion", agent(&main)).unwrap(),
        Slot::new("media2", agent(&media2)).unwrap(),
    ])
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("c.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let router = Arc::new(router);
    {
        let r = Arc::clone(&router);
        std::thread::spawn(move || {
            let _ = serve_router(listener, r);
        });
    }

    let get_root = AgentRequest::GetPubkey { role: "root".into() };
    assert_eq!(root_pubkey(request(&sock, &get_root).unwrap()), root_of(&main), "no key: the default phrase");
    assert_eq!(
        root_pubkey(request_for_key(&sock, &get_root, Some(&root_of(&media2))).unwrap()),
        root_of(&media2),
        "media2's root selects media2"
    );

    // A root signature for media2's forest is made by media2's root.
    let digest = [9u8; 32];
    let sign = AgentRequest::Sign {
        request_type: "root_device_cert".into(),
        digest: hex::encode(digest),
        origin: Some("local".into()),
        context: None,
    };
    match request_for_key(&sock, &sign, Some(&root_of(&media2))).unwrap() {
        AgentResponse::Signature { sig } => {
            crypto::verify_digest(&root_of(&media2), &digest, &hex::decode(sig).unwrap()).unwrap()
        }
        other => panic!("expected a signature, got {other:?}"),
    }

    match request(&sock, &AgentRequest::ListKeys).unwrap() {
        AgentResponse::Keys { keys } => {
            assert_eq!(keys.len(), 2);
            assert_eq!(keys[1].vault, "media2");
            assert_eq!(keys[1].root, hex::encode(root_of(&media2)));
        }
        other => panic!("expected the keys, got {other:?}"),
    }

    match request_for_key(&sock, &get_root, Some(&root_of(&phrase()))).unwrap() {
        AgentResponse::Error { code, .. } => assert_eq!(code, "no_such_key"),
        other => panic!("a key no phrase holds must be refused, got {other:?}"),
    }
}
