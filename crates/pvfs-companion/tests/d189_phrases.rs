//! PVOS D189 — two recovery phrases served by one companion, over its socket.
//!
//! A request that names a public key goes to the phrase holding it; one that
//! names none goes to the default phrase (every client before protocol v4);
//! `list_keys` lists both; a key no phrase holds is refused.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_companion::router::Slot;
use pvfs_companion::{
    request, request_for_key, request_routed, serve_router, Agent, AgentRequest, AgentResponse, ApprovalPolicy,
    ForestRef, Router, UnlockedSigner,
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

/// The companion's settings: each phrase, its keys, and the forests they
/// served — a root signature that named its forest, and an older forest
/// linked by its root — as `pvfs-companion keys --json` reports them.
#[test]
fn the_keys_report_shows_each_phrase_and_the_forests_its_keys_served() {
    let dir = tempfile::tempdir().unwrap();
    let (main, media2) = (phrase(), phrase());
    let router = Arc::new(
        Router::new(vec![
            Slot::new("companion", agent(&main)).unwrap().with_vault_path(&dir.path().join("companion.vault")),
            Slot::new("media2", agent(&media2)).unwrap().with_vault_path(&dir.path().join("media2.vault")),
        ])
        .unwrap(),
    );
    let sock = dir.path().join("c.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let r = Arc::clone(&router);
        std::thread::spawn(move || {
            let _ = serve_router(listener, r);
        });
    }

    let media = ForestRef { id: "f-media".into(), label: "media".into() };
    let sign = AgentRequest::Sign {
        request_type: "root_device_cert".into(),
        digest: hex::encode([5u8; 32]),
        origin: Some("local".into()),
        context: None,
    };
    let r = request_routed(&sock, &sign, Some(&root_of(&media2)), Some(&media)).unwrap();
    assert!(matches!(r, AgentResponse::Signature { .. }), "{r:?}");
    let lab = ForestRef { id: "f-lab".into(), label: "lab4".into() };
    let r = request_routed(&sock, &AgentRequest::LinkForest, Some(&root_of(&main)), Some(&lab)).unwrap();
    assert!(matches!(r, AgentResponse::Ok), "{r:?}");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_pvfs-companion"))
        .args(["keys", "--json", "--socket"])
        .arg(&sock)
        .env("PVFS_COMPANION_VAULT", dir.path().join("companion.vault"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["agent"], "running");
    let phrases = v["phrases"].as_array().unwrap();
    assert_eq!(phrases.len(), 2, "{v}");
    let m2 = phrases.iter().find(|p| p["vault"] == "media2").unwrap();
    assert_eq!(m2["keys"]["root"], hex::encode(root_of(&media2)));
    assert_eq!(m2["forests"][0]["forest_id"], "f-media");
    assert_eq!(m2["forests"][0]["role"], "root");
    assert_eq!(m2["forests"][0]["last_action"], "sign root_device_cert");
    let c = phrases.iter().find(|p| p["vault"] == "companion").unwrap();
    assert_eq!(c["is_default"], true);
    assert_eq!(c["forests"][0]["label"], "lab4");
    assert_eq!(c["forests"][0]["last_action"], "linked");

    // The text form says the same for a person.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_pvfs-companion"))
        .args(["keys", "--socket"])
        .arg(&sock)
        .env("PVFS_COMPANION_VAULT", dir.path().join("companion.vault"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("phrase media2") && text.contains("media (f-media)"), "{text}");
}
