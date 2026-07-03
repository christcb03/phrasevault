//! Doc 15 case C: the root lineage. A rotation re-anchors forest authority to a
//! new seed while preserving `forest_id`, ids, and history — the old root loses
//! authority atomically, the new root gains it, a recovery key can rotate, and
//! everything replays identically from a full rebuild.

use pvfs_core::{crypto, identity, Engine, TYPE_FOLDER};

fn folder(label: &str) -> pvfs_core::NodeSpec {
    pvfs_core::NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

/// Sign a one-event prepared write with `key` and commit it.
fn commit1(engine: &mut Engine, prep: pvfs_core::PreparedWrite, key: &identity::SigningKey) {
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(key, &pe.digest).unwrap());
        events.push(ev);
    }
    engine.commit_member_write(events).unwrap();
}

#[test]
fn root_rotation_moves_authority_and_survives_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, old_mn) = Engine::init(dir.path()).unwrap();
    let forest_id = engine.identity.forest_id.clone();
    let root_node = engine.identity.root_node_id.clone();
    let old_root = crypto::pubkey_bytes(&identity::root_key(&old_mn, "").unwrap());
    assert_eq!(engine.current_root().unwrap(), old_root);

    // A brand-new seed's root is the rotation target.
    let new_mn = identity::generate_mnemonic().unwrap();
    let new_root_key = identity::root_key(&new_mn, "").unwrap();
    let new_root = crypto::pubkey_bytes(&new_root_key);

    // Rotate, signed by the OLD root (it still holds authority up to this event).
    let old_root_key = identity::root_key(&old_mn, "").unwrap();
    let prep = engine.prepare_rotate_root(&old_root, &new_root).unwrap();
    commit1(&mut engine, prep, &old_root_key);

    // Authority moved: current root is the new key; forest identity is unchanged.
    assert_eq!(engine.current_root().unwrap(), new_root);
    assert_eq!(engine.identity.forest_id, forest_id);
    assert_eq!(engine.identity.root_node_id, root_node);

    // The OLD root can no longer authorize a member; the NEW root can.
    let member = crypto::pubkey_bytes(
        &identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap(),
    );
    assert!(engine.authorize_member(&old_mn, &member).is_err());
    engine.authorize_member(&new_mn, &member).unwrap();
    assert!(engine.authority_active(&member).unwrap());

    // A second rotation from the STALE old root is refused (author no longer root).
    let newer = crypto::pubkey_bytes(
        &identity::root_key(&identity::generate_mnemonic().unwrap(), "").unwrap(),
    );
    assert!(engine.prepare_rotate_root(&old_root, &newer).is_err());

    // Full rebuild replays the lineage to the same head, member intact.
    engine.close().unwrap();
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).expect("lineage survives rebuild");
    assert_eq!(engine.current_root().unwrap(), new_root);
    assert!(engine.authority_active(&member).unwrap());
    engine.close().unwrap();
}

#[test]
fn recovery_key_can_rotate_after_total_seed_loss() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let owner_root = crypto::pubkey_bytes(&identity::root_key(&owner_mn, "").unwrap());
    let owner_root_key = identity::root_key(&owner_mn, "").unwrap();

    // Register a recovery key (an independent phrase's root), signed by the root.
    let rec_mn = identity::generate_mnemonic().unwrap();
    let rec_key = identity::root_key(&rec_mn, "").unwrap();
    let rec_pub = crypto::pubkey_bytes(&rec_key);
    let prep = engine.prepare_register_recovery(&owner_root, &rec_pub).unwrap();
    commit1(&mut engine, prep, &owner_root_key);
    assert!(engine.is_recovery_key(&rec_pub).unwrap());

    // The operating seed is "compromised" — we rotate using ONLY the recovery key.
    let new_mn = identity::generate_mnemonic().unwrap();
    let new_root = crypto::pubkey_bytes(&identity::root_key(&new_mn, "").unwrap());
    let prep = engine.prepare_rotate_root(&rec_pub, &new_root).unwrap();
    commit1(&mut engine, prep, &rec_key);
    assert_eq!(engine.current_root().unwrap(), new_root);

    // A tree write under the new root still works, and history replays.
    let root_node = engine.identity.root_node_id.clone();
    let _ = engine.add_node(&root_node, folder("after-rotation")).unwrap();
    engine.close().unwrap();
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    assert_eq!(engine.current_root().unwrap(), new_root);
    engine.close().unwrap();
}

#[test]
fn recover_uses_the_current_root_not_genesis() {
    // Regression (review 2026-07-02): after a rotation, `recover` must accept the
    // NEW phrase and reject the OLD one — it previously compared against the
    // fixed genesis root, so the correct new seed was rejected and the stale old
    // seed passed (writing a device cert its author no longer had authority for).
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, old_mn) = Engine::init(dir.path()).unwrap();
    let old_root = crypto::pubkey_bytes(&identity::root_key(&old_mn, "").unwrap());
    let old_root_key = identity::root_key(&old_mn, "").unwrap();

    let new_mn = identity::generate_mnemonic().unwrap();
    let new_root = crypto::pubkey_bytes(&identity::root_key(&new_mn, "").unwrap());
    let prep = engine.prepare_rotate_root(&old_root, &new_root).unwrap();
    commit1(&mut engine, prep, &old_root_key);
    engine.close().unwrap();

    // The OLD seed no longer recovers; the NEW seed does.
    assert!(Engine::recover(dir.path(), &old_mn, 7).is_err());
    let engine = Engine::recover(dir.path(), &new_mn, 7).expect("new seed recovers");
    engine.close().unwrap();
    // And the forest still opens cleanly (the recover-authorized device is valid
    // at replay because its author is the current root).
    Engine::open(dir.path()).unwrap().close().unwrap();
}

#[test]
fn rotation_resets_recovery_keys_and_deregister_works() {
    // Doc 15 §C6a: a rotation is a clean slate — the recovery key that authored
    // it (and any others) no longer rotate. And a recovery key can be retired
    // deliberately without rotating.
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let owner_root = crypto::pubkey_bytes(&identity::root_key(&owner_mn, "").unwrap());
    let owner_key = identity::root_key(&owner_mn, "").unwrap();

    // Register two recovery keys.
    let rec1 = identity::root_key(&identity::generate_mnemonic().unwrap(), "").unwrap();
    let rec1_pub = crypto::pubkey_bytes(&rec1);
    let rec2 = identity::root_key(&identity::generate_mnemonic().unwrap(), "").unwrap();
    let rec2_pub = crypto::pubkey_bytes(&rec2);
    let p = engine.prepare_register_recovery(&owner_root, &rec1_pub).unwrap();
    commit1(&mut engine, p, &owner_key);
    let p = engine.prepare_register_recovery(&owner_root, &rec2_pub).unwrap();
    commit1(&mut engine, p, &owner_key);
    assert!(engine.is_recovery_key(&rec1_pub).unwrap());
    assert!(engine.is_recovery_key(&rec2_pub).unwrap());

    // Deregister rec1 (owner-signed) — rec2 remains.
    let p = engine.prepare_revoke_recovery(&owner_root, &rec1_pub).unwrap();
    commit1(&mut engine, p, &owner_key);
    assert!(!engine.is_recovery_key(&rec1_pub).unwrap());
    assert!(engine.is_recovery_key(&rec2_pub).unwrap());
    // Deregistering an unknown key is NotFound.
    assert!(engine.prepare_revoke_recovery(&owner_root, &rec1_pub).is_err());

    // Rotate USING rec2 — the rotation clears ALL recovery keys, incl. rec2.
    let new_mn = identity::generate_mnemonic().unwrap();
    let new_root = crypto::pubkey_bytes(&identity::root_key(&new_mn, "").unwrap());
    let p = engine.prepare_rotate_root(&rec2_pub, &new_root).unwrap();
    commit1(&mut engine, p, &rec2);
    assert_eq!(engine.current_root().unwrap(), new_root);
    assert!(!engine.is_recovery_key(&rec2_pub).unwrap(), "rotation must reset recovery keys");
    // rec2 can no longer rotate again (it was cleared).
    let newer = crypto::pubkey_bytes(
        &identity::root_key(&identity::generate_mnemonic().unwrap(), "").unwrap(),
    );
    assert!(engine.prepare_rotate_root(&rec2_pub, &newer).is_err());

    // Reset survives a full rebuild.
    engine.close().unwrap();
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    assert!(!engine.is_recovery_key(&rec2_pub).unwrap());
    engine.close().unwrap();
}

#[test]
fn a_stranger_cannot_rotate_or_register() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let stranger = crypto::pubkey_bytes(
        &identity::root_key(&identity::generate_mnemonic().unwrap(), "").unwrap(),
    );
    let target = crypto::pubkey_bytes(
        &identity::root_key(&identity::generate_mnemonic().unwrap(), "").unwrap(),
    );
    // Neither the current root nor a recovery key → both prepares refuse.
    assert!(engine.prepare_rotate_root(&stranger, &target).is_err());
    assert!(engine.prepare_register_recovery(&stranger, &target).is_err());
    engine.close().unwrap();
}
