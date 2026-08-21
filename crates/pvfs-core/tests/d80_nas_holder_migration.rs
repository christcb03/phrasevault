//! D80 — moving the NAS library from "the owner sees it over NFS" to
//! "the NAS advertises what it holds".
//!
//! Production today records all 27,565 NAS files as `file:///mnt/nas-media/...`
//! — paths on the OWNER's NFS mount. That is a fiction: the owner holds none of
//! those bytes. It is also why the NAS cannot advertise as a holder, which is
//! the topology Chris asked for from the start ("the NAS role would be an
//! advertise role and pull new file role when controller tells it to").
//!
//! Getting there means re-recording every one of those locations. That is the
//! same operation, at the same scale, as the drain that stranded 26,729 files
//! earlier in this project — so the ordering is not a detail, it is the whole
//! safety property, and these tests pin it:
//!
//!   ADD the holder's location → VERIFY every file has one → THEN retire the
//!   old one. Never the other way round.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::Lazy,
    }
}

/// Same library, two directories: what the owner sees over NFS, and what the
/// NAS actually holds. Identical bytes at identical tree paths — because that
/// is exactly the production situation.
fn library(root: &std::path::Path, n: usize) -> std::path::PathBuf {
    let media = root.join("Media");
    let season = media.join("TV").join("Show (2015)").join("Season 01");
    std::fs::create_dir_all(&season).unwrap();
    for i in 1..=n {
        // Distinct sizes so a content match is unambiguous per episode.
        std::fs::write(season.join(format!("ep{i:02}.mkv")), vec![b'a' + i as u8; 4096 + i]).unwrap();
    }
    media
}

fn files_under(engine: &Engine, folder: &str) -> Vec<String> {
    engine
        .walk(&folder.to_string())
        .unwrap()
        .into_iter()
        .filter(|e| e.node.node_type == TYPE_FILE)
        .map(|e| e.node.id)
        .collect()
}

/// Build a forest in the production shape: catalogued from the owner's NFS
/// view, so every file's only location is a path on the owner.
fn owner_with_nfs_view(
    dir: &std::path::Path,
    n: usize,
) -> (Engine, String, std::path::PathBuf, std::path::PathBuf) {
    let nfs = library(&dir.join("mnt-nas-media"), n);
    let nas = library(&dir.join("share-Data-Media"), n);

    let (mut engine, _mn) = Engine::init(dir.join("forest").as_path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Media".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();

    let sp = spec(&nfs);
    let uri = sp.source_uri.clone();
    let stats = engine.scan_unbound(&media, &uri, &sp, &mut None, 0).unwrap();
    assert_eq!(stats.added as usize, n, "the owner's NFS view catalogues the library");

    (engine, media, nfs, nas)
}

/// STEP 1 — the holder's scan must MATCH, not duplicate.
///
/// If the NAS binding its own path created a second node per file, the catalog
/// would double: 27,565 new nodes, every one of them colliding with the file it
/// is a copy of. The mechanism that prevents it is `relocated` — "a file the
/// catalog already knows, found somewhere else. No new node, only a location."
#[test]
fn the_holders_scan_relocates_it_does_not_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, _nfs, nas) = owner_with_nfs_view(dir.path(), 6);

    let before = files_under(&engine, &media);
    assert_eq!(before.len(), 6);

    let sp = spec(&nas);
    let uri = sp.source_uri.clone();
    let stats = engine.scan_unbound(&media, &uri, &sp, &mut None, 0).unwrap();

    assert_eq!(
        stats.added, 0,
        "the NAS holds the SAME library — a scan of it must add no nodes. \
         Anything above zero here is the catalog doubling, which at production \
         scale is 27,565 duplicate nodes each colliding with its own twin"
    );
    assert_eq!(stats.relocated, 6, "every file is recognised and given a second location");

    let after = files_under(&engine, &media);
    assert_eq!(after.len(), 6, "node count unchanged");
    assert_eq!(before, after, "and they are the SAME nodes, not replacements");
    engine.close().unwrap();
}

/// STEP 2 — after the holder's scan, every file has BOTH locations.
///
/// This is the state that makes the retire safe, and the state that must be
/// verified before any retire begins.
#[test]
fn every_file_carries_both_locations_before_anything_is_retired() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, nfs, nas) = owner_with_nfs_view(dir.path(), 5);

    let sp = spec(&nas);
    let uri = sp.source_uri.clone();
    engine.scan_unbound(&media, &uri, &sp, &mut None, 0).unwrap();

    for f in files_under(&engine, &media) {
        let locs = engine.locations(&f).unwrap();
        assert_eq!(locs.len(), 2, "one NFS view, one holder: {locs:?}");
        assert!(locs.iter().any(|u| u.contains(nfs.to_str().unwrap())), "{locs:?}");
        assert!(locs.iter().any(|u| u.contains(nas.to_str().unwrap())), "{locs:?}");
    }
    engine.close().unwrap();
}

/// STEP 3 — retire the NFS locations, and nothing is stranded.
///
/// The end state Chris asked for: the NAS advertises what it holds, and the
/// owner's NFS mount can go away entirely.
#[test]
fn retiring_the_nfs_view_last_strands_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, nfs, nas) = owner_with_nfs_view(dir.path(), 5);

    let sp = spec(&nas);
    let uri = sp.source_uri.clone();
    engine.scan_unbound(&media, &uri, &sp, &mut None, 0).unwrap();

    // The verify-then-retire rule, as code: only retire a file that already
    // has the holder's location.
    let mut retired = 0;
    for f in files_under(&engine, &media) {
        let locs = engine.locations(&f).unwrap();
        let has_holder = locs.iter().any(|u| u.contains(nas.to_str().unwrap()));
        assert!(has_holder, "refuse to retire a file the holder does not have");
        if let Some(old) = locs.iter().find(|u| u.contains(nfs.to_str().unwrap())) {
            let old = old.clone();
            engine.remove_location(&f, &old).unwrap();
            retired += 1;
        }
    }
    assert_eq!(retired, 5);

    for f in files_under(&engine, &media) {
        let locs = engine.locations(&f).unwrap();
        assert_eq!(locs.len(), 1, "exactly one location survives: {locs:?}");
        assert!(
            locs[0].contains(nas.to_str().unwrap()),
            "and it is the holder's, not the owner's NFS view: {locs:?}"
        );
    }
    engine.close().unwrap();
}

/// STEP 3, DONE WRONG — the drain incident, reproduced.
///
/// Retiring before the holder's location exists leaves the file with NO live
/// location at all. That is precisely what happened in production: 27,562
/// locations retired, 26,729 files left pointing nowhere. The bytes survived
/// both times, but the catalog could no longer say where anything was.
///
/// This test exists so the ordering can never be treated as a preference.
#[test]
fn retiring_first_strands_every_file() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, nfs, nas) = owner_with_nfs_view(dir.path(), 5);

    // The mistake: retire the old location before the holder has been scanned.
    for f in files_under(&engine, &media) {
        let locs = engine.locations(&f).unwrap();
        for old in locs.iter().filter(|u| u.contains(nfs.to_str().unwrap())) {
            let old = old.clone();
            engine.remove_location(&f, &old).unwrap();
        }
    }

    let stranded = files_under(&engine, &media)
        .into_iter()
        .filter(|f| engine.locations(f).unwrap().is_empty())
        .count();
    assert_eq!(
        stranded, 5,
        "every file is now stranded — this is the failure being guarded against, \
         and it is silent: the nodes are all still there and look healthy"
    );

    // And the recovery: the holder's scan finds them again, because the BYTES
    // were never the thing that was lost.
    let sp = spec(&nas);
    let uri = sp.source_uri.clone();
    let stats = engine.scan_unbound(&media, &uri, &sp, &mut None, 0).unwrap();
    assert_eq!(stats.added, 0, "recovery re-locates, it does not re-create");
    assert_eq!(stats.relocated, 5);
    let still_stranded = files_under(&engine, &media)
        .into_iter()
        .filter(|f| engine.locations(f).unwrap().is_empty())
        .count();
    assert_eq!(still_stranded, 0, "recoverable — but only because the bytes were fine");
    engine.close().unwrap();
}
