//! An empty directory is content.
//!
//! The scan only ever recorded directories it found a FILE in — `walk_disk`
//! collected files and carried the directory chain along as an attribute of
//! one. A directory holding nothing therefore had no node, and the mount could
//! not present what the catalog did not have.
//!
//! It surfaced on the D82 union swap: Radarr makes a folder for a film it is
//! monitoring before any file exists, so 29 of them vanished the moment the
//! arrs read PVFS instead of rclone. Harmless there — Radarr remakes them — but
//! the shape of a tree is not a detail a filesystem gets to summarise away, and
//! "the folder is there because something is filed in it" is not a rule real
//! directories obey.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeId, NodeSpec, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::Lazy,
    }
}

fn media(engine: &mut Engine) -> String {
    let root = engine.identity.root_node_id.clone();
    engine
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
        .unwrap()
}

fn labels(engine: &Engine, parent: &NodeId) -> Vec<String> {
    let mut v: Vec<String> = engine
        .children(parent)
        .unwrap()
        .into_iter()
        .map(|c| c.label)
        .collect();
    v.sort();
    v
}

fn child(engine: &Engine, parent: &NodeId, label: &str) -> NodeId {
    engine
        .children(parent)
        .unwrap()
        .into_iter()
        .find(|c| c.label == label)
        .unwrap_or_else(|| panic!("no child {label:?} under {parent}"))
        .node
        .id
}

/// The case from the union swap: a monitored film with no file yet.
#[test]
fn an_empty_directory_is_mirrored() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("library");
    std::fs::create_dir_all(lib.join("Movies/Waiting On This One (2028)")).unwrap();
    std::fs::create_dir_all(lib.join("Movies/Have This One (2020)")).unwrap();
    std::fs::write(
        lib.join("Movies/Have This One (2020)/film.mkv"),
        vec![7u8; 2048],
    )
    .unwrap();

    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&lib)).unwrap();
    engine.scan(Some(&m)).unwrap();

    let movies = child(&engine, &m, "Movies");
    assert_eq!(
        labels(&engine, &movies),
        vec![
            "Have This One (2020)".to_string(),
            "Waiting On This One (2028)".to_string()
        ],
        "the empty title is part of the tree, not absent from it"
    );

    // And it is a FOLDER, browsable and empty — not a stub of some other kind.
    let empty = child(&engine, &movies, "Waiting On This One (2028)");
    let node = engine.node(&empty).unwrap().unwrap();
    assert_eq!(node.node_type, TYPE_FOLDER);
    assert!(
        labels(&engine, &empty).is_empty(),
        "an empty folder stays empty"
    );
    engine.close().unwrap();
}

/// Depth is not a special case: nothing along the chain holds a file.
#[test]
fn a_chain_of_empty_directories_is_mirrored_whole() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("library");
    std::fs::create_dir_all(lib.join("TV/New Show (2026)/Season 01")).unwrap();

    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&lib)).unwrap();
    engine.scan(Some(&m)).unwrap();

    let tv = child(&engine, &m, "TV");
    let show = child(&engine, &tv, "New Show (2026)");
    let season = child(&engine, &show, "Season 01");
    assert!(
        labels(&engine, &season).is_empty(),
        "the season exists and is empty — the whole chain was mirrored"
    );
    engine.close().unwrap();
}

/// Mirroring a directory twice must not fork it — the scan is idempotent, and
/// `ensure_subfolders` is the shared path that makes it so.
#[test]
fn rescanning_does_not_duplicate_an_empty_folder() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("library");
    std::fs::create_dir_all(lib.join("Movies/Still Waiting (2029)")).unwrap();

    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&lib)).unwrap();
    engine.scan(Some(&m)).unwrap();
    engine.scan(Some(&m)).unwrap();

    let movies = child(&engine, &m, "Movies");
    assert_eq!(
        labels(&engine, &movies),
        vec!["Still Waiting (2029)".to_string()],
        "one folder after two scans"
    );
    engine.close().unwrap();
}

/// The report says what it did, so an operator can see the tree gained shape
/// rather than guessing from a file count that did not move.
#[test]
fn the_scan_reports_the_empty_ones() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("library");
    // Two with nothing in them; one with a file.
    std::fs::create_dir_all(lib.join("Movies/Empty A (2027)")).unwrap();
    std::fs::create_dir_all(lib.join("Movies/Empty B (2028)")).unwrap();
    std::fs::create_dir_all(lib.join("Movies/Full C (2020)")).unwrap();
    std::fs::write(lib.join("Movies/Full C (2020)/film.mkv"), vec![3u8; 1024]).unwrap();

    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&lib)).unwrap();
    let reports = engine.scan(Some(&m)).unwrap();

    let stats = &reports[0].stats;
    assert_eq!(stats.added, 1, "one file");
    // `Movies` itself holds no file directly either, so it counts too.
    assert_eq!(
        stats.empty_dirs, 3,
        "two empty titles plus Movies, which holds only subdirectories"
    );
    engine.close().unwrap();
}
