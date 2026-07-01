//! Integration (doc 14 §13): the multi-tenant custody agent over a Unix socket —
//! per-user get-pubkey, a trusted session that signs identity ops, the root
//! re-auth rule, and a per-action root sign.

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

use pvfs_companion::{
    serve_tenant, KdfParams, TenantAgent, TenantRequest, TenantResponse, VaultStore,
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

fn roundtrip(sock: &std::path::Path, req: &TenantRequest) -> TenantResponse {
    let mut c = UnixStream::connect(sock).unwrap();
    write_msg(&mut c, req).unwrap();
    read_msg::<_, TenantResponse>(&mut c).unwrap().unwrap()
}

#[test]
fn tenant_socket_session_and_root_reauth() {
    // A store with one app-user "alice", sealed under her password.
    let dir = tempfile::tempdir().unwrap();
    let store = VaultStore::open(dir.path()).unwrap();
    let mn = identity::generate_mnemonic().unwrap();
    let id_pub = crypto::pubkey_bytes(&identity::identity_key(&mn, "", 0).unwrap());
    store
        .create_with("alice", mn.to_string().as_bytes(), b"alice-pw", fast())
        .unwrap();

    let agent = Arc::new(TenantAgent::new(
        pvfs_companion::Sessions::new(store),
        Duration::from_secs(3600),
    ));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("tenant.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let a = Arc::clone(&agent);
        std::thread::spawn(move || {
            let _ = serve_tenant(listener, a);
        });
    }

    // get-pubkey (identity) with alice's password
    match roundtrip(
        &sock,
        &TenantRequest::GetPubkey {
            user_id: "alice".into(),
            passphrase: "alice-pw".into(),
            role: "identity".into(),
        },
    ) {
        TenantResponse::Pubkey { pubkey } => assert_eq!(pubkey, hex::encode(&id_pub)),
        other => panic!("expected pubkey, got {other:?}"),
    }

    // open a trusted session
    let token = match roundtrip(
        &sock,
        &TenantRequest::OpenSession {
            user_id: "alice".into(),
            passphrase: "alice-pw".into(),
            ttl_secs: 600,
        },
    ) {
        TenantResponse::Session { token, .. } => token,
        other => panic!("expected session, got {other:?}"),
    };

    // sign an identity op with the session -> verifies against alice's identity key
    let digest = [9u8; 32];
    match roundtrip(
        &sock,
        &TenantRequest::SignWithSession {
            token: token.clone(),
            request_type: "identity_tag".into(),
            digest: hex::encode(digest),
        },
    ) {
        TenantResponse::Signature { sig } => {
            crypto::verify_digest(&id_pub, &digest, &hex::decode(sig).unwrap()).unwrap();
        }
        other => panic!("expected signature, got {other:?}"),
    }

    // a session may NOT sign a root device cert — re-auth required
    match roundtrip(
        &sock,
        &TenantRequest::SignWithSession {
            token: token.clone(),
            request_type: "root_device_cert".into(),
            digest: hex::encode(digest),
        },
    ) {
        TenantResponse::Error { code, .. } => assert_eq!(code, "reauth_required"),
        other => panic!("expected reauth_required, got {other:?}"),
    }

    // but a per-action sign with the fresh password can
    match roundtrip(
        &sock,
        &TenantRequest::SignOnce {
            user_id: "alice".into(),
            passphrase: "alice-pw".into(),
            request_type: "root_device_cert".into(),
            digest: hex::encode(digest),
        },
    ) {
        TenantResponse::Signature { .. } => {}
        other => panic!("expected signature, got {other:?}"),
    }

    // wrong password is refused
    match roundtrip(
        &sock,
        &TenantRequest::SignOnce {
            user_id: "alice".into(),
            passphrase: "wrong".into(),
            request_type: "identity_tag".into(),
            digest: hex::encode(digest),
        },
    ) {
        TenantResponse::Error { .. } => {}
        other => panic!("expected error, got {other:?}"),
    }

    // close the session; the token no longer works
    let _ = roundtrip(&sock, &TenantRequest::CloseSession { token: token.clone() });
    match roundtrip(
        &sock,
        &TenantRequest::SignWithSession {
            token,
            request_type: "identity_tag".into(),
            digest: hex::encode(digest),
        },
    ) {
        TenantResponse::Error { code, .. } => assert_eq!(code, "no_session"),
        other => panic!("expected no_session, got {other:?}"),
    }
}
