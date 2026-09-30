//! PVOS D199 — the passes that write through the daemon's one writer, step
//! by step, leave what they always left.
//!
//! 1. An install lands in steps — the upserts first, the removals after —
//!    and ends with exactly the manifest, however many steps it takes.
//! 2. Through the daemon's writer and a read view (`SharedDb`), a commit by
//!    another connection during the install is still put right at the end.
//! 3. A catalogue pass writes only the rows that changed (part 2): a second
//!    pass over an unchanged region writes none — every pass used to upsert
//!    every row — and a changed file is one write.
//! 4. The daemon's stepped watch pass (`scan_catalogues` on a `SharedDb`)
//!    leaves the rows an engine's own scan leaves.

use std::sync::Arc;

use pvfs_core::acl::Principal;
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, RegionEntry, SharedDb, Writer, TYPE_FOLDER};

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec { node_type: TYPE_FOLDER.into(), label: label.into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
    )
    .unwrap()
}

fn row(rel: &str, size: u64, hash: &str) -> RegionEntry {
    let t = 1_700_000_000_000;
    RegionEntry {
        rel_path: rel.into(),
        kind: "file".into(),
        size_bytes: size,
        mtime_ms: t,
        changed_ms: t,
        content_hash: Some(hash.repeat(64 / hash.len().max(1))),
        quality: None,
        seen_at: 0,
    }
}

fn attest(e: &mut Engine, key: &identity::SigningKey, region: &str, seq: u64, bytes: &[u8]) {
    let hash = blake3::hash(bytes).to_hex().to_string();
    let pubkey = crypto::pubkey_bytes(key);
    let prep = e.prepare_commit_region_head(&pubkey, &region.to_string(), seq, &hash).unwrap();
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(key, &pe.digest).unwrap());
        events.push(ev);
    }
    e.commit_member_write(events).unwrap();
}

/// A forest with a catalogue region another box holds.
fn far() -> (tempfile::TempDir, Engine, identity::SigningKey, String) {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    e.authorize_member(&mn, &crypto::pubkey_bytes(&key)).unwrap();
    let far = folder(&mut e, &root, "Far");
    e.region_mark_as(&far, "catalogue", Some(&Principal::Key(crypto::pubkey_bytes(&key)))).unwrap();
    (tmp, e, key, far)
}

fn held(e: &Engine, region: &str) -> Vec<(String, u64, Option<String>)> {
    e.region_entries(&region.to_string())
        .unwrap()
        .into_iter()
        .map(|r| (r.rel_path, r.size_bytes, r.content_hash))
        .collect()
}

fn want(rows: &[RegionEntry]) -> Vec<(String, u64, Option<String>)> {
    let mut v: Vec<_> = rows.iter().map(|r| (r.rel_path.clone(), r.size_bytes, r.content_hash.clone())).collect();
    v.sort();
    v
}

/// A connection of the test's own, counting what reaches `region_entries`
/// in order (a trigger per kind of write).
fn journal(data: &std::path::Path) -> rusqlite::Connection {
    let c = rusqlite::Connection::open(data.join("index.db")).unwrap();
    c.busy_timeout(std::time::Duration::from_secs(15)).unwrap();
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS d199_ops (n INTEGER PRIMARY KEY AUTOINCREMENT, op TEXT NOT NULL);
         CREATE TRIGGER IF NOT EXISTS d199_ins AFTER INSERT ON region_entries BEGIN INSERT INTO d199_ops (op) VALUES ('put'); END;
         CREATE TRIGGER IF NOT EXISTS d199_upd AFTER UPDATE ON region_entries BEGIN INSERT INTO d199_ops (op) VALUES ('put'); END;
         CREATE TRIGGER IF NOT EXISTS d199_del AFTER DELETE ON region_entries BEGIN INSERT INTO d199_ops (op) VALUES ('del'); END;",
    )
    .unwrap();
    c
}

fn ops(c: &rusqlite::Connection) -> Vec<String> {
    let mut s = c.prepare("SELECT op FROM d199_ops ORDER BY n").unwrap();
    let v = s.query_map([], |r| r.get(0)).unwrap().collect::<Result<Vec<String>, _>>().unwrap();
    c.execute("DELETE FROM d199_ops", []).unwrap();
    v
}

#[test]
fn an_install_lands_in_steps_upserts_first_and_ends_at_the_manifest() {
    let (_tmp, mut e, key, far) = far();
    let data = e.data_dir().to_path_buf();
    let j = journal(&data);
    // Head 1: 1,300 rows — three steps of upserts.
    let head1: Vec<RegionEntry> = (0..1_300).map(|i| row(&format!("A/{i:05}.mkv"), 10 + i, "a1")).collect();
    let bytes1 = Engine::region_manifest_bytes(&far, 1, &head1);
    attest(&mut e, &key, &far, 1, &bytes1);
    ops(&j);
    let got = e.install_region_snapshot_delta(&far, 1, &bytes1, "test").unwrap();
    assert_eq!((got.rows, got.added, got.changed, got.removed), (1_300, 1_300, 0, 0));
    assert_eq!(held(&e, &far), want(&head1));
    assert_eq!(ops(&j).len(), 1_300);
    // Head 2: 1,100 of them renamed (a folder moved) and 100 changed.
    let mut head2: Vec<RegionEntry> = head1.iter().skip(1_100).map(|r| row(&r.rel_path, r.size_bytes + 1, "a2")).collect();
    head2.extend((0..1_100).map(|i| row(&format!("B/{i:05}.mkv"), 10 + i, "a1")));
    let bytes2 = Engine::region_manifest_bytes(&far, 2, &head2);
    attest(&mut e, &key, &far, 2, &bytes2);
    ops(&j);
    let got = e.install_region_snapshot_delta(&far, 2, &bytes2, "test").unwrap();
    assert_eq!((got.added, got.changed, got.removed), (1_100, 200, 1_100));
    assert_eq!(held(&e, &far), want(&head2));
    let seen = ops(&j);
    let first_del = seen.iter().position(|o| o == "del").expect("removals");
    assert!(seen[first_del..].iter().all(|o| o == "del"), "every upsert lands before the first removal");
    assert_eq!(seen.len(), 1_100 + 200 + 1_100);
}

#[test]
fn through_the_daemons_writer_a_commit_mid_install_is_still_put_right() {
    let (_tmp, mut e, key, far) = far();
    let data = e.data_dir().to_path_buf();
    let head1: Vec<RegionEntry> = (0..700).map(|i| row(&format!("S/{i:04}.mkv"), 1 + i, "b1")).collect();
    let bytes1 = Engine::region_manifest_bytes(&far, 1, &head1);
    attest(&mut e, &key, &far, 1, &bytes1);
    let writer = Arc::new(Writer::new(e));
    let db = SharedDb::new(Arc::clone(&writer), "catalogue").unwrap();
    let other = rusqlite::Connection::open(data.join("index.db")).unwrap();
    other.busy_timeout(std::time::Duration::from_secs(15)).unwrap();
    let got = pvfs_core::fs::install_region_snapshot_db(&db, &far, 1, &bytes1, "test", || {
        other
            .execute(
                "INSERT INTO region_entries
                   (region_id, rel_path, kind, size_bytes, mtime_ms, changed_ms, content_hash, quality, seen_at)
                 VALUES (?1, 'Z/stray.mkv', 'file', 9, 9, 9, NULL, NULL, 9)",
                [&far],
            )
            .unwrap();
    })
    .unwrap();
    assert_eq!((got.added, got.removed), (700, 1), "the stray row seen and removed at the end");
    drop(db);
    let e = Writer::into_engine(writer).ok().expect("no longer shared");
    assert_eq!(held(&e, &far), want(&head1));
}

fn media_region(e: &mut Engine, media: &std::path::Path) -> String {
    for i in 0..40 {
        let d = media.join(format!("Show {}", i % 4));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("e{i:02}.mkv")), format!("episode {i}")).unwrap();
    }
    let root = e.identity.root_node_id.clone();
    let local = folder(e, &root, "Local");
    e.region_mark_as(&local, "catalogue", None).unwrap();
    e.bind_folder(
        &local,
        BindSpec {
            source_uri: format!("file://{}", media.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    local
}

#[test]
fn a_pass_writes_only_the_rows_that_changed() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, _) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let media = tmp.path().join("media");
    let local = media_region(&mut e, &media);
    let j = journal(e.data_dir());
    e.scan(None).unwrap();
    assert_eq!(ops(&j).len(), 44, "the first pass writes every row: 40 files, 4 folders");
    let heads = |e: &Engine| e.region_snapshots(&local).unwrap().len();
    let published = heads(&e);
    // Nothing changed: nothing written, nothing published.
    let r = e.scan(None).unwrap();
    assert_eq!(r[0].stats.unchanged, 40);
    assert_eq!(ops(&j).len(), 0, "an unchanged pass writes no row (every pass used to upsert all 44)");
    assert_eq!(heads(&e), published, "and publishes no head");
    // One file changed, one removed: one upsert, one delete.
    std::fs::write(media.join("Show 1/e05.mkv"), "episode 5, a better copy").unwrap();
    std::fs::remove_file(media.join("Show 2/e06.mkv")).unwrap();
    let r = e.scan(None).unwrap();
    assert_eq!((r[0].stats.changed, r[0].stats.removed), (1, 1));
    assert_eq!(ops(&j), vec!["put", "del"]);
    assert_eq!(heads(&e), published + 1);
}

#[test]
fn the_daemons_stepped_pass_leaves_the_rows_an_engine_scan_leaves() {
    let rows_of = |e: &Engine, region: &str| -> Vec<(String, String, u64, Option<String>)> {
        e.region_entries(&region.to_string())
            .unwrap()
            .into_iter()
            .map(|r| (r.rel_path, r.kind, r.size_bytes, r.content_hash))
            .collect()
    };
    // The engine's own scan.
    let a = tempfile::tempdir().unwrap();
    let (mut ea, _) = Engine::init(a.path().join("forest").as_path()).unwrap();
    let la = media_region(&mut ea, &a.path().join("media"));
    ea.scan(None).unwrap();
    // The daemon's: its writer and a read view.
    let b = tempfile::tempdir().unwrap();
    let (mut eb, _) = Engine::init(b.path().join("forest").as_path()).unwrap();
    let lb = media_region(&mut eb, &b.path().join("media"));
    let writer = Arc::new(Writer::new(eb));
    {
        let db = SharedDb::new(Arc::clone(&writer), "watch").unwrap();
        let mut ctx = pvfs_core::fs::CatalogueCtx::new(None);
        let r = pvfs_core::fs::scan_catalogues(&db, &mut ctx, None, 0).unwrap();
        assert_eq!(r[0].stats.added, 40);
    }
    let eb = Writer::into_engine(writer).ok().expect("no longer shared");
    assert_eq!(rows_of(&ea, &la), rows_of(&eb, &lb));
    assert_eq!(eb.region_snapshots(&lb).unwrap().len(), 1, "the stepped pass published its head");
}
