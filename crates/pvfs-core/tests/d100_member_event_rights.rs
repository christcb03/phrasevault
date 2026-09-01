//! D100 §1 — the events that used to pass on "is this key live?" alone.
//!
//! `check_member_event` ended in `_ => {}`. A catch-all is DEFAULT-ALLOW, and
//! eleven kinds that mutate the tree fell into it — `FileLocationRemoved`,
//! `NodePurged`, `MediaQuality`, the whole link relabel/reorder/supersede/
//! suspend family, and folder bind/unbind. `LinkRemoved` sat directly above
//! them doing the per-node rights match properly.
//!
//! **Where the exposure actually was.** The prepared-write path a remote member
//! uses (`prepare_remove_location` and friends) has always checked rights of
//! its own, so this was never "any member can call an API". The hole was the
//! two paths that judge an event already in hand: `fold_one` on replay and
//! `check_member_event_batched` on a local commit. `fold_one`'s own comment
//! promises "a tampered or synced log can't carry an event its author had no
//! right to" — for eleven kinds that promise was not kept.
//!
//! Both of those paths funnel into `check_member_event`, so an assertion here
//! is an assertion about both.

use pvfs_core::event::Event;
use pvfs_core::{acl, crypto, identity, projection, Engine, NodeSpec, TYPE_FOLDER};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

/// A member authorized on the forest but granted only `rights` on a subtree.
/// The engine is CLOSED before returning: the check opens `index.db` itself,
/// and closing is the flush.
fn member_with(dir: &std::path::Path, rights: u8) -> (String, String, Vec<u8>) {
    let (mut engine, owner_mn) = Engine::init(dir).unwrap();
    let root = engine.identity.root_node_id.clone();
    let area = engine.add_node(&root, folder("area")).unwrap();
    let child = engine.add_node(&area, folder("child")).unwrap();
    let link = engine
        .children(&area)
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == child)
        .unwrap()
        .link_id;

    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member = crypto::pubkey_bytes(&key);
    engine.authorize_member(&owner_mn, &member).unwrap();
    engine
        .set_acl(&area, &acl::Principal::Key(member.clone()), rights)
        .unwrap();
    engine.close().unwrap();
    (area, link, member)
}

fn allowed(dir: &std::path::Path, ev: &Event) -> bool {
    projection::check_member_event_for_test(dir, ev, now_ms()).is_ok()
}

/// The counterpart of `FileLocationAdded`, which HAS always required write.
/// Retiring a location is how bytes stop being findable.
#[test]
fn a_reader_cannot_remove_a_file_location() {
    let dir = tempfile::tempdir().unwrap();
    let (area, _link, member) = member_with(dir.path(), acl::ACL_R);
    let ev = Event::FileLocationRemoved {
        file_id: area,
        uri: "file:///gone.mkv".into(),
        removed_at: now_ms(),
        removed_by: member,
        removal_sig: Vec::new(),
    };
    assert!(!allowed(dir.path(), &ev), "read-only must not retire a location");
}

/// Hard delete is the one that cannot be undone, so it wants admin — a member
/// holding WRITE is still refused.
#[test]
fn a_writer_cannot_purge_without_admin() {
    let dir = tempfile::tempdir().unwrap();
    let (area, _link, member) = member_with(dir.path(), acl::ACL_R | acl::ACL_W);
    let ev = Event::NodePurged {
        node_id: area,
        purged_at: now_ms(),
        author: member,
        sig: Vec::new(),
    };
    assert!(!allowed(dir.path(), &ev), "purge is admin-tier, not write-tier");
}

/// What a file IS (D76) is content about that node.
#[test]
fn a_reader_cannot_rewrite_media_quality() {
    let dir = tempfile::tempdir().unwrap();
    let (area, _link, member) = member_with(dir.path(), acl::ACL_R);
    let ev = Event::MediaQuality {
        node_id: area,
        quality: "{}".into(),
        source: "arr".into(),
        author: member,
        sig: Vec::new(),
    };
    assert!(!allowed(dir.path(), &ev), "read-only must not restate quality");
}

/// Relabelling a link is a write to its PARENT — the rule `LinkRemoved` has
/// always used, now shared by the whole family.
#[test]
fn a_reader_cannot_relabel_a_link() {
    let dir = tempfile::tempdir().unwrap();
    let (_area, link, member) = member_with(dir.path(), acl::ACL_R);
    let ev = Event::LinkRelabeled {
        link_id: link,
        label: "renamed".into(),
        author: member,
        sig: Vec::new(),
    };
    assert!(!allowed(dir.path(), &ev), "read-only must not rename a link");
}

/// Reordering is the same act by a different name, and it reached the same
/// catch-all. Named separately because a family fix that misses one member is
/// the failure mode this whole milestone is about.
#[test]
fn a_reader_cannot_reorder_a_link() {
    let dir = tempfile::tempdir().unwrap();
    let (_area, link, member) = member_with(dir.path(), acl::ACL_R);
    let ev = Event::LinkReordered {
        link_id: link,
        new_order_key: "m".into(),
        author: member,
        sig: Vec::new(),
    };
    assert!(!allowed(dir.path(), &ev), "read-only must not reorder a link");
}

/// Binding decides what a folder ingests from disk; unbinding strands every
/// location under it (D97).
#[test]
fn a_reader_cannot_unbind_a_root() {
    let dir = tempfile::tempdir().unwrap();
    let (area, _link, member) = member_with(dir.path(), acl::ACL_R);
    let ev = Event::FolderUnboundRoot {
        folder_id: area,
        source_uri: "file:///srv/media".into(),
        unbound_at: now_ms(),
        author: member,
        sig: Vec::new(),
    };
    assert!(!allowed(dir.path(), &ev), "read-only must not unbind a root");
}

/// The other half of the rule. Without this the tests above would pass just as
/// well if the check had been changed to deny everything.
#[test]
fn a_writer_is_allowed_the_write_tier_events() {
    let dir = tempfile::tempdir().unwrap();
    let (area, link, member) = member_with(dir.path(), acl::ACL_R | acl::ACL_W);

    let loc = Event::FileLocationRemoved {
        file_id: area.clone(),
        uri: "file:///gone.mkv".into(),
        removed_at: now_ms(),
        removed_by: member.clone(),
        removal_sig: Vec::new(),
    };
    assert!(
        allowed(dir.path(), &loc),
        "write on the node is exactly what retiring a location should need"
    );

    let quality = Event::MediaQuality {
        node_id: area,
        quality: "{}".into(),
        source: "arr".into(),
        author: member.clone(),
        sig: Vec::new(),
    };
    assert!(allowed(dir.path(), &quality), "quality is a write, and this is a writer");

    let relabel = Event::LinkRelabeled {
        link_id: link,
        label: "renamed".into(),
        author: member,
        sig: Vec::new(),
    };
    assert!(allowed(dir.path(), &relabel), "so is relabelling a link under it");
}
