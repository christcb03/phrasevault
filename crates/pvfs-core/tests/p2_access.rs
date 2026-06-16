//! P2 access-control foundation (doc 06 §3): external member authorization.

use pvfs_core::{crypto, identity, Engine, PvfsError};

/// A well-formed compressed secp256k1 pubkey the forest has never seen.
fn foreign_pubkey() -> Vec<u8> {
    let k = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    crypto::pubkey_bytes(&k)
}

#[test]
fn authorize_member_guards_and_survives_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let member = foreign_pubkey();

    // malformed key → BadInput
    assert!(matches!(
        engine.authorize_member(&m, &[1u8, 2, 3]),
        Err(PvfsError::BadInput { .. })
    ));

    // wrong recovery phrase → Identity (only the identity root may authorize)
    let wrong = identity::generate_mnemonic().unwrap();
    assert!(matches!(
        engine.authorize_member(&wrong, &member),
        Err(PvfsError::Identity { .. })
    ));

    // happy path, then duplicate → AlreadyExists
    engine.authorize_member(&m, &member).unwrap();
    assert!(matches!(
        engine.authorize_member(&m, &member),
        Err(PvfsError::AlreadyExists { .. })
    ));
    engine.close().unwrap();

    // the grant is a root-signed log event: it survives a full projection rebuild
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    Engine::open(dir.path())
        .expect("authorized member survives rebuild")
        .close()
        .unwrap();
}
