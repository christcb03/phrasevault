//! P0 test plan — spec §14. Each numbered area is covered at least once.

use pvfs_core::{
    Engine, FilePayload, NodeSpec, OrderKey, PvfsError, LINK_REF, TYPE_FILE, TYPE_FOLDER,
};
use rusqlite::Connection;
use std::path::Path;

fn new_forest() -> (tempfile::TempDir, Engine, pvfs_core::Mnemonic) {
    let dir = tempfile::tempdir().expect("tempdir");
    let (engine, mnemonic) = Engine::init(dir.path()).expect("init");
    (dir, engine, mnemonic)
}

fn folder_spec(label: &str, temp: bool) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: temp,
        creation_nonce: None,
    }
}

fn file_spec(label: &str, temp: bool) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FILE.into(),
        label: label.into(),
        payload: FilePayload {
            content_hash: String::new(),
            size_bytes: 1,
            mime_type: "application/octet-stream".into(),
            original_name: label.into(),
        }
        .encode(),
        is_temp: temp,
        creation_nonce: None,
    }
}

fn event_count(data_dir: &Path) -> i64 {
    let conn = Connection::open(data_dir.join("log.db")).unwrap();
    conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap()
}

fn reopen(dir: &tempfile::TempDir, engine: Engine) -> Engine {
    engine.close().unwrap();
    Engine::open(dir.path()).expect("reopen")
}

// §14.6 / §14.19 — init writes genesis; reopen is clean; identity survives rebuild
#[test]
fn init_reopen_and_rebuild_preserve_forest_identity() {
    let (dir, engine, _m) = new_forest();
    let instance = engine.identity.instance_id.clone();
    let forest = engine.identity.forest_id.clone();
    let root = engine.identity.root_node_id.clone();
    assert_eq!(event_count(dir.path()), 4); // ForestCreated, DeviceAuthorized, root node, root link

    let engine = reopen(&dir, engine);
    assert_eq!(engine.identity.instance_id, instance);
    engine.close().unwrap();

    // delete the projection entirely → full rebuild from the log
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).expect("rebuild");
    assert_eq!(engine.identity.instance_id, instance);
    assert_eq!(engine.identity.forest_id, forest);
    assert_eq!(engine.identity.root_node_id, root);
    engine.close().unwrap();
}

// §14.2 — id stability & §14.3 sign/verify
#[test]
fn ids_are_stable_and_nodes_verify() {
    let (_dir, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let a = engine
        .add_node(
            &root,
            NodeSpec {
                creation_nonce: Some(7),
                ..folder_spec("a", false)
            },
        )
        .unwrap();
    assert!(engine.verify(&a).unwrap());
    // identical spec at a later ms gets a different created_at ⇒ different id
    std::thread::sleep(std::time::Duration::from_millis(2));
    let b = engine
        .add_node(
            &root,
            NodeSpec {
                creation_nonce: Some(8),
                ..folder_spec("a", false)
            },
        )
        .unwrap();
    assert_ne!(a, b);
}

// §14.8 / §14.20 — walk order, insert-between via reorder, refs not descended
#[test]
fn walk_order_and_refs() {
    let (_dir, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let a = engine.add_node(&root, folder_spec("a", false)).unwrap();
    let b = engine.add_node(&root, folder_spec("b", false)).unwrap();
    let c = engine.add_node(&root, folder_spec("c", false)).unwrap();
    let inside_a = engine.add_node(&a, file_spec("inside-a", false)).unwrap();

    // cross-reference: c also appears in a (as a ref; not a second home)
    engine.link(&a, &c, LINK_REF, None, 0).unwrap();

    let kids: Vec<String> = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .map(|k| k.node.id)
        .collect();
    assert_eq!(kids, vec![a.clone(), b.clone(), c.clone()]);

    // move b before a by reordering
    let b_link = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|k| k.node.id == b)
        .unwrap();
    let a_key = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|k| k.node.id == a)
        .unwrap()
        .order_key;
    let new_key = OrderKey::between(None, Some(&OrderKey::parse(&a_key).unwrap())).unwrap();
    engine.reorder_link(&b_link.link_id, &new_key).unwrap();
    let kids: Vec<String> = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .map(|k| k.node.id)
        .collect();
    assert_eq!(kids, vec![b.clone(), a.clone(), c.clone()]);

    // walk: each node exactly once via contains; ref to c yielded but not descended
    let walk = engine.walk(&engine.identity.root_node_id.clone()).unwrap();
    let contains_count = walk
        .iter()
        .filter(|e| e.node.id == inside_a)
        .count();
    assert_eq!(contains_count, 1);
    let c_entries: Vec<_> = walk.iter().filter(|e| e.node.id == c).collect();
    assert_eq!(c_entries.len(), 2, "c appears under root and as ref under a");
}

// §14.20 — one-home rule
#[test]
fn one_home_rule() {
    let (_dir, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let a = engine.add_node(&root, folder_spec("a", false)).unwrap();
    let x = engine.add_node(&root, file_spec("x", false)).unwrap();

    match engine.link(&a, &x, "contains", None, 0) {
        Err(PvfsError::AlreadyContained { existing_parent, .. }) => {
            assert_eq!(existing_parent, root)
        }
        other => panic!("expected AlreadyContained, got {other:?}"),
    }
    // refs are unlimited
    engine.link(&a, &x, LINK_REF, None, 0).unwrap();

    // move: remove home then re-link
    let home = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|k| k.node.id == x && k.link_type == "contains")
        .unwrap();
    engine.remove_link(&home.link_id).unwrap();
    engine.link(&a, &x, "contains", None, 0).unwrap();
    let kids: Vec<String> = engine
        .children(&a)
        .unwrap()
        .into_iter()
        .map(|k| k.node.id)
        .collect();
    assert!(kids.contains(&x));
}

// §14.10 — cycle guard (orphan re-homing case)
#[test]
fn cycle_guard() {
    let (_dir, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let a = engine.add_node(&root, folder_spec("a", false)).unwrap();
    let b = engine.add_node(&a, folder_spec("b", false)).unwrap();

    // orphan a (b stays under a), then try to re-home a under its own child
    let a_home = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|k| k.node.id == a)
        .unwrap();
    engine.remove_link(&a_home.link_id).unwrap();
    match engine.link(&b, &a, "contains", None, 0) {
        Err(PvfsError::CycleDetected { .. }) => {}
        other => panic!("expected CycleDetected, got {other:?}"),
    }
}

// §14.7 — temp lifecycle: no events, purge on orphan, root link counts,
// cascade, rebuild drops temp
#[test]
fn temp_lifecycle() {
    let (dir, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let durable = engine.add_node(&root, folder_spec("d", false)).unwrap();
    let events_before = event_count(dir.path());

    // temp folder with a temp child; plus a ref from the durable folder
    let t1 = engine.add_node(&root, folder_spec("t1", true)).unwrap();
    let t2 = engine.add_node(&t1, file_spec("t2", true)).unwrap();
    engine.add_location(&t2, "file:///tmp/x").unwrap();
    let ref_id = engine.link(&durable, &t1, LINK_REF, None, 0).unwrap();

    assert_eq!(
        event_count(dir.path()),
        events_before,
        "temp ops must never produce events"
    );

    // removing the ref leaves the home link → still alive (root link counts)
    engine.remove_link(&ref_id).unwrap();
    assert!(engine.get_node(&t1).unwrap().is_some());

    // removing the home orphans t1 → immediate purge, cascading to t2
    let home = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|k| k.node.id == t1)
        .unwrap();
    engine.remove_link(&home.link_id).unwrap();
    assert!(engine.get_node(&t1).unwrap().is_none(), "t1 purged");
    assert!(engine.get_node(&t2).unwrap().is_none(), "cascade purged t2");
    assert_eq!(event_count(dir.path()), events_before);

    // temp does not survive a rebuild
    let t3 = engine.add_node(&root, folder_spec("t3", true)).unwrap();
    engine.close().unwrap();
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    assert!(engine.get_node(&t3).unwrap().is_none(), "rebuild drops temp");
    engine.close().unwrap();
}

// §14.9 — orphans & purge protocol
#[test]
fn orphans_and_purge() {
    let (_dir, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let a = engine.add_node(&root, folder_spec("a", false)).unwrap();
    let b = engine.add_node(&a, file_spec("b", false)).unwrap();

    // purging a linked node is refused
    match engine.purge(&[a.clone()]) {
        Err(PvfsError::NotOrphan { active_inbound, .. }) => assert_eq!(active_inbound, 1),
        other => panic!("expected NotOrphan, got {other:?}"),
    }

    // orphan a, then purge: outbound link to b is auto-removed, b becomes orphan
    let a_home = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|k| k.node.id == a)
        .unwrap();
    engine.remove_link(&a_home.link_id).unwrap();
    let orphans: Vec<String> = engine
        .list_orphans()
        .unwrap()
        .into_iter()
        .map(|n| n.id)
        .collect();
    assert!(orphans.contains(&a));

    engine.purge(&[a.clone()]).unwrap();
    assert!(engine.get_node(&a).unwrap().is_none());
    let orphans: Vec<String> = engine
        .list_orphans()
        .unwrap()
        .into_iter()
        .map(|n| n.id)
        .collect();
    assert!(orphans.contains(&b), "child of purged folder becomes orphan");
}

// §14.13 — file locations: events, same node id, soft-remove
#[test]
fn file_locations() {
    let (_dir, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let f = engine.add_node(&root, file_spec("movie.mkv", false)).unwrap();
    engine.add_location(&f, "file:///movies/movie.mkv").unwrap();
    engine.add_location(&f, "https://host/movie.mkv").unwrap();
    assert_eq!(engine.locations(&f).unwrap().len(), 2);
    // node id unchanged by location events
    assert!(engine.get_node(&f).unwrap().is_some());
    engine.remove_location(&f, "https://host/movie.mkv").unwrap();
    assert_eq!(
        engine.locations(&f).unwrap(),
        vec!["file:///movies/movie.mkv".to_string()]
    );
    // removing a non-existent location errors
    assert!(matches!(
        engine.remove_location(&f, "https://host/other"),
        Err(PvfsError::NotFound { .. })
    ));
}

// §14.16/§14.17 — link logical id conflicts surface as AlreadyExists
#[test]
fn duplicate_link_conflicts() {
    let (_dir, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let a = engine.add_node(&root, folder_spec("a", false)).unwrap();
    let x = engine.add_node(&root, file_spec("x", false)).unwrap();
    engine.link(&a, &x, LINK_REF, None, 0).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    match engine.link(&a, &x, LINK_REF, None, 0) {
        Err(PvfsError::AlreadyExists { kind, .. }) => assert_eq!(kind, "link"),
        other => panic!("expected AlreadyExists, got {other:?}"),
    }
    // a different nonce creates a parallel edge
    engine.link(&a, &x, LINK_REF, None, 1).unwrap();
}

// §14.5/§14.6/§14.11 — projection fold + catch-up + rebuild equivalence
#[test]
fn rebuild_matches_live_projection() {
    let (dir, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let a = engine.add_node(&root, folder_spec("a", false)).unwrap();
    let f = engine.add_node(&a, file_spec("f", false)).unwrap();
    engine.add_location(&f, "file:///x").unwrap();
    let live: Vec<(String, usize)> = engine
        .walk(&root)
        .unwrap()
        .into_iter()
        .map(|e| (e.node.id, e.depth))
        .collect();
    engine.close().unwrap();

    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    let rebuilt: Vec<(String, usize)> = engine
        .walk(&root)
        .unwrap()
        .into_iter()
        .map(|e| (e.node.id, e.depth))
        .collect();
    assert_eq!(live, rebuilt);
    assert_eq!(engine.locations(&f).unwrap(), vec!["file:///x".to_string()]);
    engine.close().unwrap();
}

// §14.11/§14.15 — a tampered log event breaks the chain ⇒ fatal, refuses open
#[test]
fn tampered_log_refuses_open() {
    let (dir, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    engine.add_node(&root, folder_spec("a", false)).unwrap();
    engine.close().unwrap();

    // tamper: flip a byte in the last event body
    {
        let conn = Connection::open(dir.path().join("log.db")).unwrap();
        let (seq, mut body): (i64, Vec<u8>) = conn
            .query_row(
                "SELECT seq, body FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let last = body.len() - 1;
        body[last] ^= 0xFF;
        conn.execute(
            "UPDATE events SET body = ?1 WHERE seq = ?2",
            rusqlite::params![body, seq],
        )
        .unwrap();
    }
    // force the full agreement check (as after a crash)
    {
        let conn = Connection::open(dir.path().join("index.db")).unwrap();
        conn.execute(
            "UPDATE projection_meta SET v = '0' WHERE k = 'clean_shutdown'",
            [],
        )
        .unwrap();
    }
    match Engine::open(dir.path()) {
        Err(PvfsError::LogChainBroken { .. }) | Err(PvfsError::Corruption { .. }) => {}
        other => panic!("expected chain-broken/corruption, got {:?}", other.map(|_| ())),
    }
}

// §14.21 — device certificates: authorize, revoke blocks new appends, recover
#[test]
fn device_certificates() {
    let (dir, mut engine, mnemonic) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let device0 = engine.device_pubkey();

    // authorize device 1, then revoke device 0
    engine.authorize_device(&mnemonic, 1).unwrap();
    engine.revoke_device(&mnemonic, &device0).unwrap();

    // our own (revoked) key may no longer author new records
    match engine.add_node(&root, folder_spec("nope", false)) {
        Err(PvfsError::Integrity { .. }) => {}
        other => panic!("expected Integrity (revoked device), got {other:?}"),
    }
    engine.close().unwrap();

    // recover as device 1 from the mnemonic and continue working
    let mut engine = Engine::recover(dir.path(), &mnemonic, 1).unwrap();
    engine.add_node(&root, folder_spec("ok", false)).unwrap();
    engine.close().unwrap();
}

// §14.12 — error contract basics
#[test]
fn error_contract() {
    let (_dir, mut engine, _m) = new_forest();
    let root = engine.identity.root_node_id.clone();
    assert!(matches!(
        engine.add_node(&"deadbeef".to_string(), folder_spec("x", false)),
        Err(PvfsError::NotFound { .. })
    ));
    assert!(matches!(
        engine.add_node(&root, folder_spec("", false)),
        Err(PvfsError::BadInput { .. })
    ));
    let big = "x".repeat(5000);
    assert!(matches!(
        engine.add_node(&root, folder_spec(&big, false)),
        Err(PvfsError::BadInput { .. })
    ));
}
