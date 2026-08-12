//! P7.2a (doc 20 §2.3) — physical region logs: the mark-time split, event
//! routing, the unmark seal, generation files, tree replay, and the
//! causal-isolation guards.

use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, event, identity, log_store, Engine, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

fn file(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FILE.into(),
        label: label.into(),
        payload: pvfs_core::FilePayload::default().encode(),
        is_temp: false,
        creation_nonce: None,
    }
}

/// Count rows in a region generation file directly.
fn log_rows(path: &std::path::Path) -> i64 {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    conn.query_row("SELECT IFNULL(MAX(seq),0) FROM events", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn mark_splits_and_routes_subtree_events_to_the_region_log() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let photos = e.add_node(&root, folder("photos")).unwrap();

    let tip_before_mark = e.log_tip().unwrap();
    e.region_mark(&photos).unwrap();
    // the mark commit = RegionMarked + RegionBaseline in the top log
    assert_eq!(e.log_tip().unwrap(), tip_before_mark + 2);
    let info = e
        .region_info(&photos)
        .unwrap()
        .expect("a fresh mark splits");
    assert_eq!(info.baseline_seq, tip_before_mark + 2);
    assert_eq!(info.baseline_log, "");
    assert_eq!(info.tip_seq, 0, "no region events yet");

    // writes inside the region no longer touch the top log
    let top_frozen = e.log_tip().unwrap();
    let summer = e.add_node(&photos, folder("summer")).unwrap();
    let pic = e.add_node(&summer, file("pic.jpg")).unwrap();
    assert_eq!(e.log_tip().unwrap(), top_frozen, "top log is frozen for region writes");
    let gen = dir
        .path()
        .join(info.log_file.as_deref().expect("generation file recorded"));
    assert!(gen.exists(), "generation file created by the first region write");
    assert_eq!(log_rows(&gen), 4, "two nodes + two homing links");

    // writes outside still author in the top log
    let _music = e.add_node(&root, folder("music")).unwrap();
    assert_eq!(e.log_tip().unwrap(), top_frozen + 2);

    // reads are log-agnostic
    assert_eq!(e.region_of(&pic).unwrap(), photos);
    assert_eq!(e.children(&summer).unwrap().len(), 1);
    e.close().unwrap();
}

#[test]
fn unmark_seals_and_a_remark_starts_a_fresh_generation() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let photos = e.add_node(&root, folder("photos")).unwrap();
    e.region_mark(&photos).unwrap();
    let _x = e.add_node(&photos, folder("x")).unwrap();
    let gen1 = dir
        .path()
        .join(e.region_info(&photos).unwrap().unwrap().log_file.unwrap());
    let gen1_rows = log_rows(&gen1);

    // seal: final head + unmark author in the top log; the file stays put
    let top_before = e.log_tip().unwrap();
    e.region_unmark(&photos).unwrap();
    assert_eq!(e.log_tip().unwrap(), top_before + 2, "SubRegionHead + RegionUnmarked");
    assert!(e.region_info(&photos).unwrap().is_none());
    assert!(gen1.exists(), "sealed generations remain for verification");

    // subsequent subtree writes author in the top log again
    let top_after = e.log_tip().unwrap();
    let _y = e.add_node(&photos, folder("y")).unwrap();
    assert_eq!(e.log_tip().unwrap(), top_after + 2);
    assert_eq!(log_rows(&gen1), gen1_rows, "sealed log untouched");

    // re-mark: a fresh generation with a different file
    e.region_mark(&photos).unwrap();
    let info2 = e.region_info(&photos).unwrap().unwrap();
    let gen2 = dir.path().join(info2.log_file.as_deref().unwrap());
    assert_ne!(gen1, gen2, "a re-mark starts a new generation file");
    let _z = e.add_node(&photos, folder("z")).unwrap();
    assert_eq!(log_rows(&gen2), 2);
    assert_eq!(log_rows(&gen1), gen1_rows, "old generation still sealed");
    e.close().unwrap();
}

#[test]
fn tree_rebuild_replays_active_nested_and_sealed_regions() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    // photos (active region) / albums (nested, sealed later) ; docs (sealed)
    let photos = e.add_node(&root, folder("photos")).unwrap();
    let docs = e.add_node(&root, folder("docs")).unwrap();
    e.region_mark(&photos).unwrap();
    let albums = e.add_node(&photos, folder("albums")).unwrap();
    e.region_mark(&albums).unwrap();
    let summer = e.add_node(&albums, folder("summer")).unwrap();
    let pic = e.add_node(&summer, file("pic.jpg")).unwrap();
    e.region_mark(&docs).unwrap();
    let letter = e.add_node(&docs, file("letter.txt")).unwrap();
    // seal docs, and seal nested albums back into photos
    e.region_unmark(&docs).unwrap();
    e.region_unmark(&albums).unwrap();
    // post-seal writes land where they now belong
    let tax = e.add_node(&docs, file("tax.pdf")).unwrap();
    let extra = e.add_node(&albums, folder("extra")).unwrap();
    let expect_regions = e.regions().unwrap();
    e.close().unwrap();

    // force a full rebuild: the tree replay must reproduce everything,
    // verifying each baseline commitment and each seal along the way
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let e2 = Engine::open(dir.path()).unwrap();
    assert_eq!(e2.regions().unwrap(), expect_regions);
    assert_eq!(e2.region_of(&pic).unwrap(), photos, "albums sealed back into photos");
    assert_eq!(e2.region_of(&extra).unwrap(), photos);
    assert_eq!(e2.region_of(&tax).unwrap(), root);
    for n in [&photos, &docs, &albums, &summer, &pic, &letter, &tax, &extra] {
        assert!(e2.get_node(n).unwrap().is_some(), "node {n} must survive rebuild");
    }
    assert_eq!(e2.children(&summer).unwrap().len(), 1);
    assert_eq!(e2.children(&docs).unwrap().len(), 2);
    e2.close().unwrap();
}

#[test]
fn close_attests_region_heads() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let photos = e.add_node(&root, folder("photos")).unwrap();
    e.region_mark(&photos).unwrap();
    let _a = e.add_node(&photos, folder("a")).unwrap();
    let info = e.region_info(&photos).unwrap().unwrap();
    assert_eq!(info.committed_seq, 0, "no head attested yet");
    assert_eq!(info.tip_seq, 2);
    e.close().unwrap();

    let e2 = Engine::open(dir.path()).unwrap();
    let info = e2.region_info(&photos).unwrap().unwrap();
    assert_eq!(info.committed_seq, info.tip_seq, "close committed the head");
    assert!(!info.committed_head.is_empty());
    e2.close().unwrap();
}

#[test]
fn causal_isolation_guards_purge_and_orphan_adoption() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let photos = e.add_node(&root, folder("photos")).unwrap();
    let inner = e.add_node(&photos, folder("inner")).unwrap();
    let music = e.add_node(&root, folder("music")).unwrap();
    e.region_mark(&photos).unwrap();

    // orphan a node INSIDE the region; its region stays sticky
    let stray = e.add_node(&inner, folder("stray")).unwrap();
    let home = e
        .children(&inner)
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == stray)
        .unwrap()
        .link_id;
    e.remove_link(&home).unwrap();
    assert_eq!(e.region_of(&stray).unwrap(), photos, "orphan keeps its region");

    // adopting the region's orphan under a top-region parent is a cross-region
    // move — since P7.2c it authors as a NodeMovedIn and the sticky region flips
    e.link(&music, &stray, pvfs_core::LINK_CONTAINS, None, 1)
        .expect("cross-region adoption is the paired protocol now");
    assert_eq!(
        e.region_of(&stray).unwrap(),
        e.identity.root_node_id,
        "adoption flipped the orphan's region to the destination"
    );
    // put it back to an orphan inside the region for the purge check below
    let adopt_home = e
        .children(&music)
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == stray)
        .unwrap()
        .link_id;
    e.remove_link(&adopt_home).unwrap();

    // purging it IS allowed (all-region cascade); the tombstone keeps replay
    // order-free (doc 20 §2.5)
    e.purge(std::slice::from_ref(&stray)).unwrap();
    assert!(e.get_node(&stray).unwrap().is_none());

    // purging a subtree that CONTAINS a boundary is refused
    // (orphan `photos` first so only the region rule can refuse it)
    let photos_home = e
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == photos)
        .unwrap()
        .link_id;
    let err = e.remove_link(&photos_home).map(|_| ()).and_then(|_| e.purge(std::slice::from_ref(&photos)));
    let err = err.unwrap_err();
    assert!(
        err.to_string().contains("unmark"),
        "purge-through-boundary must point at unmark: {err}"
    );
    e.close().unwrap();
}

#[test]
fn legacy_p70_marks_split_lazily_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let photos = e.add_node(&root, folder("photos")).unwrap();
    e.close().unwrap();

    // forge a P7.0-era bare mark (no baseline) straight into the top log,
    // signed by the real device key — exactly what an upgraded forest holds
    let dev = identity::device_key(&mn, "", 0).unwrap();
    let me = crypto::pubkey_bytes(&dev);
    {
        let conn = rusqlite::Connection::open(dir.path().join("log.db")).unwrap();
        let tip: i64 = conn
            .query_row("SELECT IFNULL(MAX(seq),0) FROM events", [], |r| r.get(0))
            .unwrap();
        let (prev, written_at): (Vec<u8>, i64) = conn
            .query_row(
                "SELECT chain_hash, written_at FROM events WHERE seq = ?1",
                [tip],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let t = written_at as u64 + 1;
        let sig = crypto::sign_digest(&dev, &event::msg_region_marked(&photos, t, &me)).unwrap();
        let ev = event::Event::RegionMarked {
            node_id: photos.clone(),
            marked_at: t,
            author: me,
            sig,
        };
        let prev = <[u8; 32]>::try_from(prev.as_slice()).unwrap();
        let chain = log_store::chain_step(&prev, tip as u64 + 1, ev.kind(), &ev.encode_body(), t);
        conn.execute(
            "INSERT INTO events (seq, kind, body, chain_hash, written_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![tip + 1, ev.kind(), ev.encode_body(), chain.as_slice(), t],
        )
        .unwrap();
        // the projection didn't fold this — poison the clean flag so the
        // open self-heals exactly as a real upgrade/crash would
        let idx = rusqlite::Connection::open(dir.path().join("index.db")).unwrap();
        idx.execute(
            "UPDATE projection_meta SET v = '0' WHERE k = 'clean_shutdown'",
            [],
        )
        .unwrap();
    }

    // opening rebuilds (unclean), folds the legacy mark, then lazily splits it
    let mut e2 = Engine::open(dir.path()).unwrap();
    let info = e2
        .region_info(&photos)
        .unwrap()
        .expect("legacy mark split at open");
    assert_eq!(info.baseline_log, "");
    // and the region routes like any other from here on
    let top = e2.log_tip().unwrap();
    let _inside = e2.add_node(&photos, folder("inside")).unwrap();
    assert_eq!(e2.log_tip().unwrap(), top);
    e2.close().unwrap();

    // the whole thing still rebuilds cleanly from scratch
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let e3 = Engine::open(dir.path()).unwrap();
    assert!(e3.region_info(&photos).unwrap().is_some());
    e3.close().unwrap();
}

#[test]
fn purge_tombstone_keeps_cross_log_replay_order_free() {
    // The P7.2c resurrection scenario (doc 20 §2.5): a node is CREATED in
    // region A's log, moves to the top region (adoption), and is purged there
    // — so its creation and its purge live in different logs. Tree replay
    // folds the top log (with the purge) before A's log (with the creation);
    // without the tombstone the node would resurrect and every later baseline
    // would diverge.
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let area = e.add_node(&root, folder("area")).unwrap();
    e.region_mark(&area).unwrap();
    let doomed = e.add_node(&area, folder("doomed")).unwrap(); // created in A's log
    let home = e
        .children(&area)
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == doomed)
        .unwrap()
        .link_id;
    e.remove_link(&home).unwrap(); // orphan (still region A, sticky)
    e.link(&root, &doomed, pvfs_core::LINK_CONTAINS, None, 7)
        .unwrap(); // adoption → region flips to top
    assert_eq!(e.region_of(&doomed).unwrap(), root);
    let adopt_home = e
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == doomed)
        .unwrap()
        .link_id;
    e.remove_link(&adopt_home).unwrap();
    e.purge(std::slice::from_ref(&doomed)).unwrap(); // purge in the TOP log
    assert!(e.get_node(&doomed).unwrap().is_none());
    e.close().unwrap();

    // full rebuild: top log (purge) replays before region A's log (creation)
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let e2 = Engine::open(dir.path()).unwrap();
    assert!(
        e2.get_node(&doomed).unwrap().is_none(),
        "the tombstone must prevent resurrection across parallel logs"
    );
    e2.close().unwrap();
}

#[test]
fn member_rights_inside_regions_replay_identically() {
    // ACL grants on region nodes live in the region log; a rebuild must
    // reproduce the same effective rights (doc 20 §2.2 Q-B4).
    let dir = tempfile::tempdir().unwrap();
    let (mut e, mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let photos = e.add_node(&root, folder("photos")).unwrap();
    e.region_mark(&photos).unwrap();
    let member = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member);
    e.authorize_member(&mn, &member_pub).unwrap();
    e.set_acl(&photos, &Principal::Key(member_pub.clone()), acl::ACL_R | acl::ACL_W)
        .unwrap();
    let before = e
        .effective_rights(&Principal::Key(member_pub.clone()), &photos)
        .unwrap();
    assert_eq!(before, acl::ACL_R | acl::ACL_W);
    e.close().unwrap();

    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let e2 = Engine::open(dir.path()).unwrap();
    assert_eq!(
        e2.effective_rights(&Principal::Key(member_pub), &photos).unwrap(),
        before,
        "region-log ACLs survive the tree rebuild"
    );
    e2.close().unwrap();
}
