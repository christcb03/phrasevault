//! Integration (doc 14 §9 phase 2b): the companion agent over a Unix socket —
//! get-pubkey, an approved sign (signature verifies), and a policy denial.

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use pvfs_companion::{
    Agent, AgentRequest, AgentResponse, ApprovalPolicy, KdfParams, UnlockedSigner, Vault,
};
use pvfs_core::{crypto, identity};
use pvfs_proto::{read_msg, write_msg};

fn fast() -> KdfParams {
    KdfParams {
        m_cost: 32,
        t_cost: 1,
        p_cost: 1,
    }
}

fn unlock(phrase: &str) -> UnlockedSigner {
    UnlockedSigner::from_phrase(phrase).unwrap()
}

#[test]
fn agent_socket_pubkey_sign_and_deny() {
    let mn = identity::generate_mnemonic().unwrap();
    let phrase = mn.to_string();
    let root_pub = crypto::pubkey_bytes(&identity::root_key(&mn, "").unwrap());

    // seal + unlock into a signer
    let vdir = tempfile::tempdir().unwrap();
    let vpath = vdir.path().join("v.json");
    Vault::create_with(&vpath, phrase.as_bytes(), b"pw", fast()).unwrap();
    let secret = Vault::open(&vpath).unwrap().unseal(b"pw").unwrap();
    let phrase = std::str::from_utf8(&secret).unwrap().to_string();

    // an interactive-equivalent policy that approves root events
    let agent = Arc::new(Agent::new(
        unlock(&phrase),
        ApprovalPolicy {
            auto_root: true,
            ..Default::default()
        },
    ));

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("agent.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let a = Arc::clone(&agent);
        std::thread::spawn(move || {
            let _ = pvfs_companion::serve(listener, a);
        });
    }

    let mut c = UnixStream::connect(&sock).unwrap();

    // get-pubkey root -> matches the forest root key
    write_msg(&mut c, &AgentRequest::GetPubkey { role: "root".into() }).unwrap();
    match read_msg::<_, AgentResponse>(&mut c).unwrap().unwrap() {
        AgentResponse::Pubkey { pubkey } => assert_eq!(pubkey, hex::encode(&root_pub)),
        other => panic!("expected pubkey, got {other:?}"),
    }

    // sign a digest (approved) -> the signature verifies against the root key
    let digest = [7u8; 32];
    write_msg(
        &mut c,
        &AgentRequest::Sign {
            request_type: "root_device_cert".into(),
            digest: hex::encode(digest),
            origin: Some("local".into()),
        },
    )
    .unwrap();
    match read_msg::<_, AgentResponse>(&mut c).unwrap().unwrap() {
        AgentResponse::Signature { sig } => {
            let sig = hex::decode(sig).unwrap();
            crypto::verify_digest(&root_pub, &digest, &sig).unwrap();
        }
        other => panic!("expected signature, got {other:?}"),
    }

    // a headless agent with default policy denies a root event
    let deny = Agent::new(unlock(&phrase), ApprovalPolicy::default());
    let resp = deny.handle(AgentRequest::Sign {
        request_type: "root_device_cert".into(),
        digest: hex::encode(digest),
        origin: Some("local".into()),
    });
    assert!(matches!(resp, AgentResponse::Error { ref code, .. } if code == "denied"));
}
