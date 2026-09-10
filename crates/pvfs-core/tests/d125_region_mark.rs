//! D125 item 6 — `region mark --catalogue [--owner]`: one signed event with
//! a trailing kind, an optional admin grant in the same batch, and the
//! preconditions that keep a catalogue region node-free and single-kinded.

use pvfs_core::acl::{self, Principal};
use pvfs_core::event::{Event, K_REGION_MARKED};
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_FOLDER};

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

fn kinds_after(data: &std::path::Path, seq: u64) -> Vec<String> {
    let c = rusqlite::Connection::open_with_flags(
        data.join("log.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut s = c.prepare("SELECT kind FROM events WHERE seq > ?1 ORDER BY seq").unwrap();
    s.query_map([seq as i64], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect()
}

/// One event, no baseline, no generation file — and the kind survives a full
/// replay from the log (decode + the v2 preimage + the fold).
#[test]
fn a_catalogue_mark_is_one_event_with_no_baseline_and_no_log() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let lib = folder(&mut e, &root, "Library");
    let tip = e.log_tip().unwrap();
    e.region_mark_as(&lib, "catalogue", None).unwrap();
    assert_eq!(kinds_after(dir.path(), tip), vec!["RegionMarked"], "no RegionBaseline: nothing is split");
    let info = e.region_info(&lib).unwrap().expect("a region");
    assert_eq!((info.kind.as_str(), info.log_file.as_deref(), info.tip_seq), ("catalogue", None, 0));
    assert_eq!(
        e.regions().unwrap().into_iter().map(|(id, _, k)| (id, k)).collect::<Vec<_>>(),
        vec![(lib.clone(), "catalogue".to_string())]
    );
    e.close().unwrap();

    // Full replay: the projection is rebuilt from the log alone.
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let e = Engine::open(dir.path()).unwrap();
    let info = e.region_info(&lib).unwrap().expect("still a region after replay");
    assert_eq!((info.kind.as_str(), info.log_file.as_deref()), ("catalogue", None));
}

/// `--owner` is an admin grant on the region in the SAME batch — the one
/// right a replica needs to publish the region's head.
#[test]
fn a_catalogue_mark_with_an_owner_grants_admin_in_the_same_batch() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let lib = folder(&mut e, &root, "Library");
    let holder_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let holder = Principal::Key(crypto::pubkey_bytes(&holder_key));
    e.authorize_member(&mn, &crypto::pubkey_bytes(&holder_key)).unwrap();
    assert_eq!(e.effective_rights(&holder, &lib).unwrap() & acl::ACL_A, 0, "no admin before");

    let tip = e.log_tip().unwrap();
    e.region_mark_as(&lib, "catalogue", Some(&holder)).unwrap();
    assert_eq!(kinds_after(dir.path(), tip), vec!["RegionMarked", "AclSet"]);
    assert_ne!(e.effective_rights(&holder, &lib).unwrap() & acl::ACL_A, 0, "admin on the region");
    assert_eq!(e.effective_rights(&holder, &root).unwrap() & acl::ACL_A, 0, "and nowhere above it");
}

/// A catalogue region holds rows, never nodes, and its kind is fixed: a folder
/// with children is refused, a second mark of any kind is refused, and a log
/// region cannot be turned into one.
#[test]
fn a_catalogue_mark_takes_an_empty_folder_once() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let full = folder(&mut e, &root, "Full");
    folder(&mut e, &full, "Sub");
    let err = e.region_mark_as(&full, "catalogue", None).expect_err("has children");
    assert!(err.to_string().contains("children"), "{err}");

    let empty = folder(&mut e, &root, "Empty");
    e.region_mark_as(&empty, "catalogue", None).unwrap();
    let tip = e.log_tip().unwrap();
    assert!(e.region_mark_as(&empty, "catalogue", None).is_err(), "marked once");
    let err = e.region_mark(&empty).expect_err("a log re-mark would split it");
    assert!(err.to_string().contains("catalogue"), "{err}");
    assert_eq!(e.log_tip().unwrap(), tip, "refusals append nothing");

    let photos = folder(&mut e, &root, "Photos");
    e.region_mark(&photos).unwrap();
    let err = e.region_mark_as(&photos, "catalogue", None).expect_err("already a log region");
    assert!(err.to_string().contains("log region"), "{err}");
    assert!(e.region_mark_as(&photos, "shelf", None).is_err(), "not a kind");
}

/// Wire compatibility: a log mark encodes exactly as before D125 (no trailing
/// field), a catalogue mark round-trips its kind, and a present-but-empty
/// kind is rejected as non-canonical.
#[test]
fn a_log_mark_is_the_old_bytes_and_a_catalogue_mark_round_trips() {
    let mk = |kind: &str| Event::RegionMarked {
        node_id: "n".repeat(64),
        marked_at: 7,
        kind: kind.into(),
        author: vec![1; 32],
        sig: vec![2; 64],
    };
    let old = mk("").encode_body();
    let new = mk("catalogue").encode_body();
    assert_eq!(&new[..old.len()], &old[..], "the old fields come first, unchanged");
    assert!(new.len() > old.len(), "and the kind trails");
    match Event::decode(K_REGION_MARKED, &old).unwrap() {
        Event::RegionMarked { kind, .. } => assert_eq!(kind, ""),
        other => panic!("{other:?}"),
    }
    match Event::decode(K_REGION_MARKED, &new).unwrap() {
        Event::RegionMarked { kind, .. } => assert_eq!(kind, "catalogue"),
        other => panic!("{other:?}"),
    }
    // A present, zero-length kind (a u32 LE length prefix of 0): the
    // canonical form omits it, so this must be refused, not read as a log.
    let mut bad = old.clone();
    bad.extend_from_slice(&0u32.to_le_bytes());
    let err = Event::decode(K_REGION_MARKED, &bad).expect_err("an empty kind must be omitted");
    assert!(err.to_string().contains("empty kind"), "{err}");
}
