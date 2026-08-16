//! The projection is a pure, rebuildable cache — a TORN cache must
//! self-heal, never brick the forest. Found live by the D69 fleet: a
//! projection torn by concurrent folders passed the position probes but
//! had lost its device_keys rows, so the tail fold refused the forest's
//! OWN device ("author not authorized") and every open failed — while a
//! cold rebuild of the same log was perfect. startup_check now routes a
//! failed tail fold to full_rebuild like every other cache-suspect
//! condition.

use pvfs_core::{Engine, NodeSpec, TYPE_FOLDER};

#[test]
fn torn_projection_self_heals_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    // Device-authored tail events past genesis.
    for label in ["a", "b", "c"] {
        engine
            .add_node(
                &root,
                NodeSpec {
                    node_type: TYPE_FOLDER.into(),
                    label: label.into(),
                    payload: Vec::new(),
                    is_temp: false,
                    creation_nonce: None,
                },
            )
            .unwrap();
    }
    engine.close().unwrap();

    // The tear, exactly as captured in the D69 forensics: the fold
    // watermark claims an early position (so the tail replays), while the
    // authorization table has LOST its rows — a torn write-set between
    // concurrent folders. Clean-shutdown stays "1": the probes must not
    // save us via the crash path; the FOLD itself must.
    let db = dir.path().join("index.db");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute("DELETE FROM device_keys", []).unwrap();
    conn.execute("UPDATE applied_marks SET seq = 2 WHERE log_id = ''", [])
        .unwrap();
    // The chain hash at the rewound mark must AGREE (the position probe
    // checks it — if it disagreed, the PROBE would heal us and this test
    // would pass for the wrong reason). The chain lives in log.db.
    let log = rusqlite::Connection::open(dir.path().join("log.db")).unwrap();
    let chain: Vec<u8> = log
        .query_row("SELECT chain_hash FROM events WHERE seq = 2", [], |r| r.get(0))
        .unwrap();
    drop(log);
    conn.execute(
        "UPDATE applied_marks SET chain_hash = ?1 WHERE log_id = ''",
        rusqlite::params![hex::encode(&chain)],
    )
    .unwrap();
    drop(conn);

    // Before the fix this open died with "author not authorized" on the
    // forest's own device. Now: self-heal (full rebuild) and serve.
    let engine = Engine::open(dir.path()).expect("a torn cache must self-heal, not brick");
    let labels: Vec<String> = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .map(|c| c.node.label)
        .collect();
    for want in ["a", "b", "c"] {
        assert!(labels.contains(&want.to_string()), "tree intact after heal: {labels:?}");
    }
}

#[test]
fn torn_device_table_at_tip_self_heals() {
    // The EXACT shape from the D69 forensics: applied mark AT TIP (nothing
    // to fold — the tail path never runs) and device_keys EMPTY. The device
    // check after open must treat the cache as suspect, rebuild, and serve
    // — not refuse the forest's own device forever.
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "kept".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine.close().unwrap();

    let conn = rusqlite::Connection::open(dir.path().join("index.db")).unwrap();
    conn.execute("DELETE FROM device_keys", []).unwrap();
    drop(conn);

    let mut engine = Engine::open(dir.path()).expect("torn device table must self-heal");
    // And the healed forest WRITES — the device is active again.
    engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "post-heal".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .expect("device active after heal");
}
