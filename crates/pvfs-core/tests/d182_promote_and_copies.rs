//! PVOS D182 — promotion as one atomic step, whoever holds the root, with
//! defaults that survive a second move; and dated, verified copies of the log.

use pvfs_core::{crypto, identity, Engine, NodeSpec, PvfsError, ReplicaSource, TYPE_FOLDER};

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec {
            node_type: TYPE_FOLDER.into(),
            label: label.into(),
            payload: Vec::new(),
            is_temp: false,
            creation_nonce: None,
        },
    )
    .unwrap()
}

/// A replica of the data dir `owner` at `dir` — the owner's log plus a marker.
fn replica_of(owner: &std::path::Path, dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    for f in ["log.db", "log.db-wal", "log.db-shm"] {
        if owner.join(f).exists() {
            std::fs::copy(owner.join(f), dir.join(f)).unwrap();
        }
    }
    ReplicaSource { transport: "tcp".into(), target: "192.0.2.1:7421".into(), pin: "7".repeat(64), region: String::new() }
        .save(dir)
        .unwrap();
}

fn tip(dir: &std::path::Path) -> u64 {
    pvfs_core::mount::peek_tip(dir).unwrap().0
}

fn live_owner_devices(e: &Engine) -> Vec<Vec<u8>> {
    e.devices()
        .unwrap()
        .into_iter()
        .filter(|d| d.revoked_at.is_none())
        .map(|d| hex::decode(d.pubkey).unwrap())
        .collect()
}

#[test]
fn a_promotion_that_cannot_revoke_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
    let (owner, mn) = Engine::init(&a).unwrap();
    owner.close().unwrap();
    replica_of(&a, &b);
    let before = tip(&b);

    // D128's two appends let this half-finish: the device authorized, the
    // marker gone, the revoke refused. Now nothing is written at all.
    let stranger = crypto::pubkey_bytes(&identity::generate_device_key());
    match Engine::promote_with_phrase(&b, &mn, 1, &[stranger]) {
        Err(PvfsError::NotFound { kind: "device", .. }) => {}
        Err(e) => panic!("expected the unknown device refused, got {e}"),
        Ok(_) => panic!("expected the unknown device refused, got a promotion"),
    }
    assert_eq!(tip(&b), before, "nothing was appended");
    assert!(b.join("replica").exists() && !b.join("promoted-from").exists(), "still a replica");
    assert!(!b.join("device.key").exists());
    let still = Engine::open(&b).unwrap();
    assert!(still.is_replica());
    still.close().unwrap();
}

#[test]
fn a_root_signer_promotes_without_the_phrase_and_a_refusal_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
    let (mut owner, mn) = Engine::init(&a).unwrap();
    let root = owner.identity.root_node_id.clone();
    folder(&mut owner, &root, "Before");
    let old = live_owner_devices(&owner);
    owner.close().unwrap();
    replica_of(&a, &b);
    let before = tip(&b);
    let root_key = identity::root_key(&mn, "").unwrap();
    let root_pub = crypto::pubkey_bytes(&root_key);

    // The companion says no: nothing changes.
    let refused = Engine::promote_with_root_signer(&b, &root_pub, identity::generate_device_key(), 1, &old, |_| {
        Err(PvfsError::Forbidden { action: "companion sign".into(), reason: "denied at the prompt".into() })
    });
    assert!(matches!(refused, Err(PvfsError::Forbidden { .. })));
    assert_eq!(tip(&b), before);
    assert!(b.join("replica").exists());

    // The companion approves: a device key made here, root signatures from
    // "the vault" — both events in one append, at the tip.
    let device = identity::generate_device_key();
    let device_pub = crypto::pubkey_bytes(&device);
    let mut e = Engine::promote_with_root_signer(&b, &root_pub, device, 1, &old, |d| crypto::sign_digest(&root_key, d)).unwrap();
    assert_eq!(e.device_pubkey(), device_pub);
    assert_eq!(e.log_tip().unwrap(), before + 2);
    folder(&mut e, &root, "After");
    e.close().unwrap();
    // The random key is the device from now on: it opens and writes.
    let mut again = Engine::open(&b).unwrap();
    assert_eq!(again.device_pubkey(), device_pub);
    folder(&mut again, &root, "Again");
    again.close().unwrap();

    // A root that is not this forest's is refused before anything happens.
    let c = tmp.path().join("c");
    replica_of(&a, &c);
    let wrong = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let r = Engine::promote_with_root_signer(&c, &crypto::pubkey_bytes(&wrong), identity::generate_device_key(), 1, &[], |d| {
        crypto::sign_digest(&wrong, d)
    });
    assert!(matches!(r, Err(PvfsError::Identity { .. })));
    assert!(c.join("replica").exists());
}

#[test]
fn the_owner_moves_there_and_back_and_each_move_revokes_the_live_owner() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b, a2) = (tmp.path().join("a"), tmp.path().join("b"), tmp.path().join("a2"));
    let (owner, mn) = Engine::init(&a).unwrap();
    owner.close().unwrap();

    // Move 1: b becomes the owner (the CLI's default: next index, revoke
    // every live owner device — here device 0).
    replica_of(&a, &b);
    let revoke = { let r = Engine::open(&b).unwrap(); let v = live_owner_devices(&r); r.close().unwrap(); v };
    assert_eq!(revoke.len(), 1);
    let e = Engine::promote_with_phrase(&b, &mn, 1, &revoke).unwrap();
    e.close().unwrap();

    // Move 2, back: the old box rejoins as a replica of b (a fresh dir) and is
    // promoted. D128's default ("device 0") would revoke NOBODY here — device 0
    // is already revoked — leaving b's device 1 live beside the new owner.
    replica_of(&b, &a2);
    let (revoke, next) = {
        let r = Engine::open(&a2).unwrap();
        let v = live_owner_devices(&r);
        let next = r.devices().unwrap().iter().map(|d| d.index + 1).max().unwrap();
        r.close().unwrap();
        (v, next)
    };
    assert_eq!(next, 2, "the next index never used");
    assert_eq!(revoke.len(), 1, "exactly the live owner device: b's");
    let e = Engine::promote_with_phrase(&a2, &mn, next, &revoke).unwrap();
    let devices = e.devices().unwrap();
    let live: Vec<u64> = devices.iter().filter(|d| d.revoked_at.is_none()).map(|d| d.index).collect();
    assert_eq!(live, vec![2], "one owner device is live after the round trip");
    e.close().unwrap();
}

#[test]
fn a_dated_copy_verifies_restores_and_a_damaged_one_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("forest").join(".pvfs");
    let (mut owner, _mn) = Engine::init(&data).unwrap();
    let root = owner.identity.root_node_id.clone();
    let forest = owner.identity.forest_id.clone();
    for i in 0..5 {
        folder(&mut owner, &root, &format!("f{i}"));
    }
    let (seq, hash) = owner.log_tip_hash().unwrap();
    // Beside a live writer: the copy is a consistent snapshot.
    let copy = tmp.path().join("backups").join("c1");
    let files = pvfs_core::backup::copy_logs(&data, &copy).unwrap();
    owner.close().unwrap();
    assert_eq!(files, vec![std::path::PathBuf::from("log.db")]);
    let v = pvfs_core::backup::verify_copy(&copy).unwrap();
    assert_eq!((v.forest_id.as_str(), v.seq, v.hash.as_slice()), (forest.as_str(), seq, hash.as_slice()));
    assert!(!tmp.path().join("backups").read_dir().unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with(".pvfs-verify")),
        "the scratch replica is gone");

    // Restore: a replica that opens at the copy's tip, following nothing yet.
    let restored = tmp.path().join("restored");
    let r = pvfs_core::backup::restore(&copy, &restored, None).unwrap();
    assert_eq!(r.seq, seq);
    let e = Engine::open(&restored.join(".pvfs")).unwrap();
    assert!(e.is_replica());
    assert_eq!(e.log_tip().unwrap(), seq);
    e.close().unwrap();
    assert!(matches!(pvfs_core::backup::restore(&copy, &restored, None), Err(PvfsError::AlreadyExists { .. })));

    // A copy with one row altered is not a copy of this forest's log.
    let bad = tmp.path().join("backups").join("c2");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::copy(copy.join("log.db"), bad.join("log.db")).unwrap();
    let c = rusqlite::Connection::open(bad.join("log.db")).unwrap();
    c.execute("UPDATE events SET written_at = written_at + 1 WHERE seq = 3", []).unwrap();
    drop(c);
    assert!(pvfs_core::backup::verify_copy(&bad).is_err(), "a damaged copy must not verify");
}
