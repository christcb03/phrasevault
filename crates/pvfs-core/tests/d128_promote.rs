//! D128 — a replica becomes the forest's writer, once, with the recovery
//! phrase; the old writer is revoked; the log is one unbroken chain.

use pvfs_core::{Engine, NodeSpec, ReplicaSource, TYPE_FOLDER};

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

/// A replica of `owner_dir` at `dir`: the same log (a replica is exactly
/// that — the owner's log, shipped and verified) plus the marker that says
/// where it follows from.
fn replica_of(owner_dir: &std::path::Path, dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::copy(owner_dir.join("log.db"), dir.join("log.db")).unwrap();
    for side in ["log.db-wal", "log.db-shm"] {
        if owner_dir.join(side).exists() {
            std::fs::copy(owner_dir.join(side), dir.join(side)).unwrap();
        }
    }
    ReplicaSource {
        transport: "tcp".into(),
        target: "192.0.2.1:7421".into(),
        pin: "7".repeat(64),
        region: String::new(),
    }
    .save(dir)
    .unwrap();
}

#[test]
fn a_replica_is_promoted_with_the_phrase_and_the_old_writer_is_revoked() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    let (mut owner, mn) = Engine::init(&a).unwrap();
    let root = owner.identity.root_node_id.clone();
    folder(&mut owner, &root, "Before");
    let old_device = owner.devices().unwrap();
    assert_eq!(old_device.len(), 1, "the forest's one device, index 0");
    let old_pub = hex::decode(&old_device[0].0).unwrap();
    let tip_a = owner.log_tip().unwrap();
    owner.close().unwrap();

    replica_of(&a, &b);
    let premise = Engine::open(&b).unwrap();
    assert!(premise.is_replica(), "premise: b is a replica");
    premise.close().unwrap();

    // Promote b as device 1, revoking a's device 0.
    let mut b_engine = Engine::promote(&b, &mn, 1, Some(old_pub.as_slice())).unwrap();
    assert!(!b_engine.is_replica());
    assert_eq!(b_engine.log_tip().unwrap(), tip_a + 2, "DeviceAuthorized + DeviceRevoked, at the tip");
    let devices = b_engine.devices().unwrap();
    assert_eq!(devices.len(), 2);
    assert!(devices[0].3.is_some(), "device 0 (the old owner) is revoked");
    assert_eq!((devices[1].1, devices[1].3), (1, None), "device 1 (this box) is live");
    let after = folder(&mut b_engine, &root, "After");
    assert!(b_engine.children(&root).unwrap().iter().any(|c| c.node.id == after), "b appends");
    b_engine.close().unwrap();
    assert!(b.join("promoted-from").exists() && !b.join("replica").exists(), "the old source is kept as evidence");

    // Re-open: an owner now, and stays one.
    let again = Engine::open(&b).unwrap();
    assert!(!again.is_replica());
    again.close().unwrap();

    // A second promotion is refused: it is not a replica any more.
    let err = match Engine::promote(&b, &mn, 2, None) {
        Ok(_) => panic!("a second promotion must be refused"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("not a replica"), "{err}");
}

#[test]
fn a_wrong_phrase_leaves_the_replica_a_replica() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    let (owner, _mn) = Engine::init(&a).unwrap();
    owner.close().unwrap();
    replica_of(&a, &b);
    let wrong = pvfs_core::identity::generate_mnemonic().unwrap();
    assert!(Engine::promote(&b, &wrong, 1, None).is_err());
    assert!(b.join("replica").exists() && !b.join("promoted-from").exists(), "the marker went back");
    let still = Engine::open(&b).unwrap();
    assert!(still.is_replica());
    still.close().unwrap();
}
