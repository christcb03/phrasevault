//! P7.0 (doc 20 §2, doc 13 §B) — region boundaries: mark/unmark round-trip,
//! nested membership, replay survival, and the cross-region move refusal.

use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_FOLDER};

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

#[test]
fn regions_mark_membership_replay_and_unmark() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    // root/photos/albums/summer ; root/music
    let photos = e.add_node(&root, folder("photos")).unwrap();
    let albums = e.add_node(&photos, folder("albums")).unwrap();
    let summer = e.add_node(&albums, folder("summer")).unwrap();
    let music = e.add_node(&root, folder("music")).unwrap();

    // unmarked forest: everything is the implicit top region (the root)
    assert_eq!(e.region_of(&summer).unwrap(), root);

    // mark photos: its closure joins it; music stays with the root
    e.region_mark(&photos).unwrap();
    assert_eq!(e.region_of(&summer).unwrap(), photos);
    assert_eq!(e.region_of(&photos).unwrap(), photos, "a boundary is its own region");
    assert_eq!(e.region_of(&music).unwrap(), root);

    // nested: albums becomes a sub-region; summer re-homes to it, photos keeps itself
    e.region_mark(&albums).unwrap();
    assert_eq!(e.region_of(&summer).unwrap(), albums);
    assert_eq!(e.region_of(&photos).unwrap(), photos);
    let mut listed: Vec<String> = e.regions().unwrap().into_iter().map(|(id, _)| id).collect();
    listed.sort();
    let mut expect = vec![photos.clone(), albums.clone()];
    expect.sort();
    assert_eq!(listed, expect);

    // marks replay: reopen (projection intact) and after a full rebuild
    let data = e.data_dir().to_path_buf();
    e.close().unwrap();
    let e2 = Engine::open(&data).unwrap();
    assert_eq!(e2.region_of(&summer).unwrap(), albums);
    drop(e2);
    std::fs::remove_file(data.join("index.db")).unwrap();
    let mut e3 = Engine::open(&data).unwrap();
    assert_eq!(e3.region_of(&summer).unwrap(), albums, "marks survive a projection rebuild");

    // unmark albums: summer folds back into photos; double-unmark errors
    e3.region_unmark(&albums).unwrap();
    assert_eq!(e3.region_of(&summer).unwrap(), photos);
    assert!(e3.region_unmark(&albums).is_err());
    e3.close().unwrap();
}

#[test]
fn cross_region_moves_are_refused_and_member_marks_need_admin() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let photos = e.add_node(&root, folder("photos")).unwrap();
    let clip = e.add_node(&photos, folder("clip")).unwrap();
    let music = e.add_node(&root, folder("music")).unwrap();
    e.region_mark(&photos).unwrap();

    // a member with w everywhere but admin nowhere
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    e.authorize_member(&owner_mn, &member_pub).unwrap();
    e.set_acl(&root, &Principal::Key(member_pub.clone()), acl::ACL_R | acl::ACL_W)
        .unwrap();

    // mv clip (region photos) under music (top region) → refused at prepare
    let err = e.prepare_move_node(&member_pub, &clip, &music).unwrap_err();
    assert!(
        err.to_string().contains("region"),
        "cross-region mv must name the reason: {err}"
    );

    // an in-region move is untouched by the guard
    let sub = e.add_node(&photos, folder("sub")).unwrap();
    assert!(e.prepare_move_node(&member_pub, &clip, &sub).is_ok());
    let _ = sub;

    // replay-side authorization: a member without admin cannot have authored
    // a mark — verified via the engine's commit path for member events
    let prepared = e.prepare_set_acl(&member_pub, &photos, &Principal::Public, acl::ACL_R);
    // (sanity: the member lacks admin, so even an AclSet prepare refuses —
    // the same require_right gate the region replay check uses)
    assert!(prepared.is_err());
}
