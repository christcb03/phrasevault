//! PVOS D188 — a retired owner's endpoint is no longer dialed.
//!
//! A promotion revokes the old owner's device key, but its endpoint record
//! stayed in `.fleet/endpoints`: every box's catalogue job dialed it each
//! pass and the new owner's health job paged "peer down" for it forever
//! (lab4's retired owner, `.119:7481`, shows it). A record written by a
//! revoked DEVICE key is now skipped; a follower's record, written with its
//! member key, is not.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::Client;
use pvfs_core::acl::{self, Principal};
use pvfs_core::identity::DeviceKeyCache;
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn node(label: &str, payload: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: payload.as_bytes().to_vec(),
        is_temp: false,
        creation_nonce: None,
    }
}

#[test]
fn a_revoked_devices_endpoint_is_skipped_and_a_members_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let data = owner.data_dir().to_path_buf();
    let old_device = owner.device_pubkey();

    // The old owner announced itself: its device key wrote the record.
    let fleet = owner.add_node(&root, node(".fleet", "")).unwrap();
    let eps = owner.add_node(&fleet, node("endpoints", "")).unwrap();
    owner.add_node(&eps, node("pin-old-owner", "10.0.0.1:7434")).unwrap();

    // A follower announces itself with its member key, through the owner.
    let member = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member);
    owner.authorize_member(&mn, &member_pub).unwrap();
    owner.set_acl(&root, &Principal::Key(member_pub.clone()), acl::ACL_R).unwrap();
    owner.set_acl(&eps, &Principal::Key(member_pub.clone()), acl::ACL_R | acl::ACL_W).unwrap();
    let daemon = Arc::new(Daemon::new(owner));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = daemon.clone();
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let m2 = member.clone();
    let mut as_member =
        Client::connect_signed(&sock, &member_pub, move |d| crypto::sign_digest(&m2, d).unwrap()).unwrap();
    as_member
        .add_node(&eps, "pin-follower", "fleet.endpoint", b"10.0.0.2:7434", |d| {
            crypto::sign_digest(&member, d).unwrap()
        })
        .unwrap();
    drop(as_member);
    drop(daemon);

    // Before the promotion both are dialed.
    let e = Engine::open(&data).unwrap();
    let mut pins: Vec<String> = pvfs_client::fetch::catalog_endpoints(&e).into_keys().collect();
    pins.sort();
    assert_eq!(pins, vec!["pin-follower", "pin-old-owner"]);
    e.close().unwrap();

    // The promotion: a new owner device admitted, the old one revoked, the
    // data dir now holding the new device's key.
    let mut e = Engine::open(&data).unwrap();
    e.authorize_device(&mn, 1).unwrap();
    e.revoke_device(&mn, &old_device).unwrap();
    e.close().unwrap();
    DeviceKeyCache { signing_key: identity::device_key(&mn, "", 1).unwrap(), device_index: 1 }
        .save(&data)
        .unwrap();

    let e = Engine::open(&data).unwrap();
    assert!(e.is_revoked_device(&old_device).unwrap());
    assert!(!e.is_revoked_device(&member_pub).unwrap(), "a member key is never a revoked device");
    let eps_now = pvfs_client::fetch::catalog_endpoints(&e);
    assert_eq!(eps_now.keys().collect::<Vec<_>>(), vec!["pin-follower"], "the retired owner is not dialed");
    assert_eq!(eps_now["pin-follower"], "10.0.0.2:7434");
    // Who announced what stays on record (the fence's evidence rule reads it).
    assert!(pvfs_client::fetch::catalog_endpoint_authors(&e).contains_key("pin-old-owner"));
    e.close().unwrap();
}
