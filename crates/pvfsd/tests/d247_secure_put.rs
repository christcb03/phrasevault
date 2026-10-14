//! PVOS D247 — a secure put lands only when it commits. The daemon stages
//! the uploaded ciphertext beside the blob and the commit places it: a put
//! whose commit is refused leaves the old bytes readable and no staged file;
//! a good put serves the new bytes, leaves nothing staged, and the old bytes
//! are gone from disk (the deletability contract).

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_SECURE};
use pvfsd::{serve, Daemon};

fn staged_beside(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.contains(".pvfs-staged-"))
        .collect()
}

#[test]
fn a_secure_put_lands_only_when_it_commits() {
    let dir = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let blob = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_SECURE.into(),
                label: "keychain.enc".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    let blob_path = store.path().join("keychain.enc");
    engine.add_location(&blob, &pvfs_core::storage::path_to_uri(&blob_path).unwrap()).unwrap();

    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let me = crypto::pubkey_bytes(&key);
    engine.authorize_member(&owner_mn, &me).unwrap();
    engine.set_acl(&blob, &Principal::Key(me.clone()), acl::ACL_R | acl::ACL_W).unwrap();

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(engine));
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });
    let sign = |d: &[u8; 32]| crypto::sign_digest(&key, d).unwrap();
    let mut c = Client::connect_signed(&sock, &me, sign).unwrap();

    // v1 lands
    c.secure_put(&blob, b"secret v1", sign).unwrap();
    assert_eq!(c.secure_cat(&blob).unwrap(), b"secret v1");
    assert_eq!(std::fs::read(&blob_path).unwrap(), b"secret v1");
    assert!(staged_beside(store.path()).is_empty(), "nothing left staged");

    // a put whose commit is refused (a signature that does not verify)
    let bad = c.secure_put(&blob, b"never committed", |_d| vec![0u8; 64]);
    assert!(matches!(bad, Err(ClientError::Server { .. })), "the commit is refused: {bad:?}");
    assert_eq!(c.secure_cat(&blob).unwrap(), b"secret v1", "the old secret is still readable");
    assert_eq!(std::fs::read(&blob_path).unwrap(), b"secret v1", "and still on disk");
    assert!(staged_beside(store.path()).is_empty(), "the refused put took its staged bytes with it");

    // v2 lands; v1's bytes are gone from disk
    c.secure_put(&blob, b"secret v2", sign).unwrap();
    assert_eq!(c.secure_cat(&blob).unwrap(), b"secret v2");
    assert_eq!(std::fs::read(&blob_path).unwrap(), b"secret v2", "the old bytes went with the rename");
    assert!(staged_beside(store.path()).is_empty());
}
