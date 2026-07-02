//! P3 phase 1 (doc 12 §8): the secure-blob kernel — a content-free ledger with
//! last-write-wins projection, write-gated authors (live AND at commit), and
//! full replay/rebuild parity. No plaintext, no ciphertext, ever touches the log.

use pvfs_core::{acl, crypto, identity, Engine, NodeSpec, Principal, PvfsError, TYPE_SECURE};

fn secure(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_SECURE.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: pvfs_core::TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

/// Sign each prepared event with `sign` and commit (the two-phase member path).
fn commit_with(
    engine: &mut Engine,
    prep: pvfs_core::PreparedWrite,
    sign: impl Fn(&[u8; 32]) -> Vec<u8>,
) -> pvfs_core::Result<()> {
    let signed: Vec<_> = prep
        .events
        .into_iter()
        .map(|pe| {
            let mut ev = pe.event;
            ev.set_author_sig(sign(&pe.digest));
            ev
        })
        .collect();
    engine.commit_member_write(signed)
}

#[test]
fn secure_ledger_last_write_wins_and_survives_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let blob = engine.add_node(&root, secure("messenger.db")).unwrap();

    // No head before the first update.
    assert!(engine.secure_current(&blob).unwrap().is_none());

    // The owner device advances the ledger.
    let dev = identity::device_key(&mn, "", 0).unwrap();
    let dev_pub = crypto::pubkey_bytes(&dev);
    let h1 = [0x11u8; 32];
    let prep = engine.prepare_secure_update(&dev_pub, &blob, &h1, 100).unwrap();
    commit_with(&mut engine, prep, |d| crypto::sign_digest(&dev, d).unwrap()).unwrap();
    let (h, size, _t, author) = engine.secure_current(&blob).unwrap().unwrap();
    assert_eq!(h, h1.to_vec());
    assert_eq!(size, 100);
    assert_eq!(author, dev_pub);

    // Second update replaces the head — one row, no history in the projection.
    let h2 = [0x22u8; 32];
    let prep = engine.prepare_secure_update(&dev_pub, &blob, &h2, 64).unwrap();
    commit_with(&mut engine, prep, |d| crypto::sign_digest(&dev, d).unwrap()).unwrap();
    let (h, size, _t, _a) = engine.secure_current(&blob).unwrap().unwrap();
    assert_eq!((h, size), (h2.to_vec(), 64));

    // The ledger is log events: a full projection rebuild replays to the same head.
    engine.close().unwrap();
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).expect("secure ledger survives rebuild");
    let (h, size, _t, _a) = engine.secure_current(&blob).unwrap().unwrap();
    assert_eq!((h, size), (h2.to_vec(), 64));
    engine.close().unwrap();
}

#[test]
fn secure_updates_are_write_gated_live_and_at_commit() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let blob = engine.add_node(&root, secure("shared.db")).unwrap();

    // A member with NO grant on the blob: refused at prepare.
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&mn, &member).unwrap();
    let h = [0x33u8; 32];
    assert!(matches!(
        engine.prepare_secure_update(&member, &blob, &h, 1),
        Err(PvfsError::Forbidden { .. })
    ));

    // Granted w: the member's update commits.
    engine
        .set_acl(&blob, &Principal::Key(member.clone()), acl::ACL_W)
        .unwrap();
    let prep = engine.prepare_secure_update(&member, &blob, &h, 10).unwrap();
    commit_with(&mut engine, prep, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();
    assert_eq!(engine.secure_current(&blob).unwrap().unwrap().3, member);

    // TOCTOU: prepared while granted, committed after the grant is cleared —
    // the commit re-check must refuse it (same rule replay enforces).
    let prep = engine.prepare_secure_update(&member, &blob, &h, 11).unwrap();
    engine.set_acl(&blob, &Principal::Key(member.clone()), 0).unwrap();
    let refused = commit_with(&mut engine, prep, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    });
    assert!(refused.is_err(), "revoked writer must not advance the ledger");
    engine.close().unwrap();
}

#[test]
fn secure_put_read_overwrite_and_tamper() {
    let dir = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let blob = engine.add_node(&root, secure("vault.enc")).unwrap();
    let blob_path = store.path().join("vault.enc");
    let uri = pvfs_core::storage::path_to_uri(&blob_path).unwrap();

    // No location yet: put refuses before touching anything.
    assert!(matches!(
        engine.secure_put_local(&blob, b"x"),
        Err(PvfsError::BadInput { .. })
    ));
    engine.add_location(&blob, &uri).unwrap();

    // Put v1: bytes land, ledger head matches, read verifies.
    let h1 = engine.secure_put_local(&blob, b"ciphertext-one").unwrap();
    assert_eq!(engine.secure_read(&blob).unwrap(), b"ciphertext-one");
    assert_eq!(engine.secure_current(&blob).unwrap().unwrap().0, h1.to_vec());

    // Overwrite: the OLD BYTES ARE GONE from disk — the deletability contract.
    let h2 = engine.secure_put_local(&blob, b"v2").unwrap();
    assert_ne!(h1, h2);
    assert_eq!(std::fs::read(&blob_path).unwrap(), b"v2");
    assert!(engine.secure_verify(&blob).unwrap());

    // Tampered location bytes: verify says no, read refuses with Integrity.
    std::fs::write(&blob_path, b"evil bytes").unwrap();
    assert!(!engine.secure_verify(&blob).unwrap());
    assert!(matches!(
        engine.secure_read(&blob),
        Err(PvfsError::Integrity { .. })
    ));

    // A fresh put repairs the blob (new bytes, new signed head).
    engine.secure_put_local(&blob, b"v3").unwrap();
    assert!(engine.secure_verify(&blob).unwrap());
    engine.close().unwrap();
}

#[test]
fn secure_location_rules() {
    let dir = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let blob = engine.add_node(&root, secure("one.enc")).unwrap();
    let uri_a = pvfs_core::storage::path_to_uri(&store.path().join("a.enc")).unwrap();
    let uri_b = pvfs_core::storage::path_to_uri(&store.path().join("b.enc")).unwrap();

    // Exactly one location (doc 12 §8.3): a second, different one is refused;
    // re-adding the same one is the usual idempotent no-op.
    engine.add_location(&blob, &uri_a).unwrap();
    engine.add_location(&blob, &uri_a).unwrap();
    assert!(matches!(
        engine.add_location(&blob, &uri_b),
        Err(PvfsError::BadInput { .. })
    ));

    // Folders still take no locations; file nodes are untouched by all this.
    let folder_node = engine.add_node(&root, folder("plain")).unwrap();
    assert!(matches!(
        engine.add_location(&folder_node, &uri_b),
        Err(PvfsError::BadInput { .. })
    ));
    engine.close().unwrap();
}

#[test]
fn secure_prepare_rejects_wrong_targets() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let plain = engine.add_node(&root, folder("docs")).unwrap();
    let dev = identity::device_key(&mn, "", 0).unwrap();
    let dev_pub = crypto::pubkey_bytes(&dev);
    let h = [0u8; 32];

    // A non-secure node cannot grow a ledger.
    assert!(matches!(
        engine.prepare_secure_update(&dev_pub, &plain, &h, 1),
        Err(PvfsError::BadInput { .. })
    ));
    // An unknown node is NotFound.
    assert!(matches!(
        engine.prepare_secure_update(&dev_pub, &"ab".repeat(32), &h, 1),
        Err(PvfsError::NotFound { .. })
    ));
    engine.close().unwrap();
}
