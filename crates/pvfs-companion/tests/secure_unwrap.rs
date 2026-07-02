//! Integration (doc 12 §8.5): the companion unwraps a secure-blob content key
//! over the socket — the encryption key never leaves the agent, and a plaintext
//! sealed to the owner round-trips through seal → socket-unwrap → open.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_companion::{Agent, ApprovalPolicy, KeyRole, UnlockedSigner};
use pvfs_core::envelope;

#[test]
fn companion_unwraps_a_secure_blob_key_over_the_socket() {
    let mn = pvfs_core::identity::generate_mnemonic().unwrap();
    let signer = UnlockedSigner::from_phrase(&mn.to_string()).unwrap();
    // The owner's encryption pubkey (2'/0') — what a blob is sealed to.
    let enc_pub = signer.pubkey(KeyRole::Encryption).unwrap();

    let agent = Arc::new(Agent::new(signer, ApprovalPolicy::default()));
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let a = Arc::clone(&agent);
        std::thread::spawn(move || {
            let _ = pvfs_companion::serve(listener, a);
        });
    }

    // Seal a plaintext to the owner, parse, and unwrap via the socket.
    let sealed = envelope::seal(b"top secret", &[enc_pub.clone()]).unwrap();
    let env = envelope::parse(&sealed).unwrap();
    let wrap = env.wrap_for(&enc_pub).unwrap();

    let resp = pvfs_companion::request(
        &sock,
        &pvfs_companion::AgentRequest::SecureUnwrap {
            ephemeral_pubkey: hex::encode(&wrap.ephemeral_pubkey),
            nonce: hex::encode(&wrap.nonce),
            wrapped_key: hex::encode(&wrap.wrapped_key),
        },
    )
    .unwrap();
    let ck = match resp {
        pvfs_companion::AgentResponse::ContentKey { content_key } => {
            <[u8; 32]>::try_from(hex::decode(content_key).unwrap()).unwrap()
        }
        other => panic!("expected a content key, got {other:?}"),
    };
    assert_eq!(envelope::open_with_key(&env, &ck).unwrap(), b"top secret");

    // A garbage wrap is refused, not answered with a bogus key.
    let resp = pvfs_companion::request(
        &sock,
        &pvfs_companion::AgentRequest::SecureUnwrap {
            ephemeral_pubkey: hex::encode(&wrap.ephemeral_pubkey),
            nonce: hex::encode(&wrap.nonce),
            wrapped_key: hex::encode([0u8; 48]),
        },
    )
    .unwrap();
    assert!(matches!(resp, pvfs_companion::AgentResponse::Error { .. }));
}
