//! D81 4a — one folder, many roots.
//!
//! Chris: "We need to be able to combine multiple physical locations, whether
//! that be different volumes on one machine or different machines into one
//! cohesive location for the library. My thought is to allow the same folder to
//! be bound to multiple trees in different locations on the read side."
//!
//! Before this, `folder_id` was a PRIMARY KEY. A second bind was refused on an
//! owner and — worse — silently REPLACED the first on a replica, which is how a
//! two-volume NAS was inexpressible rather than merely unsupported.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::OnAdd,
    }
}

/// Two directories standing in for `Data` and `Data_ext`: one library, split.
fn two_volumes(root: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let warm = root.join("Data");
    let cold = root.join("Data_ext");
    std::fs::create_dir_all(warm.join("Movies/Warm Title (2020)")).unwrap();
    std::fs::create_dir_all(cold.join("Movies/Cold Title (1998)")).unwrap();
    std::fs::write(warm.join("Movies/Warm Title (2020)/warm.mkv"), vec![1u8; 3000]).unwrap();
    std::fs::write(cold.join("Movies/Cold Title (1998)/cold.mkv"), vec![2u8; 4000]).unwrap();
    (warm, cold)
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

#[test]
fn one_folder_takes_two_roots() {
    let dir = tempfile::tempdir().unwrap();
    let (warm, cold) = two_volumes(dir.path());
    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);

    engine.bind_folder(&m, spec(&warm)).unwrap();
    engine.bind_folder(&m, spec(&cold)).unwrap();

    let roots = engine.bindings_for(&m).unwrap();
    assert_eq!(roots.len(), 2, "both volumes are roots of the one library");
    engine.close().unwrap();
}

/// The same directory twice is a mistake; a second, different one is not.
#[test]
fn the_same_root_twice_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (warm, _cold) = two_volumes(dir.path());
    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);

    engine.bind_folder(&m, spec(&warm)).unwrap();
    let err = engine.bind_folder(&m, spec(&warm)).unwrap_err().to_string();
    assert!(err.contains("already a root"), "{err}");
    assert_eq!(engine.bindings_for(&m).unwrap().len(), 1);
    engine.close().unwrap();
}

/// ONE pass covers every root — the property the whole design rests on.
#[test]
fn a_scan_walks_every_root_of_the_folder() {
    let dir = tempfile::tempdir().unwrap();
    let (warm, cold) = two_volumes(dir.path());
    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&warm)).unwrap();
    engine.bind_folder(&m, spec(&cold)).unwrap();

    let reports = engine.scan(Some(&m)).unwrap();
    let added: u64 = reports.iter().map(|r| r.stats.added).sum();
    assert_eq!(added, 2, "one file from each volume: {reports:?}");

    let names: Vec<String> = engine
        .walk(&m)
        .unwrap()
        .into_iter()
        .filter(|e| e.node.node_type == TYPE_FILE)
        .map(|e| e.node.label)
        .collect();
    assert!(names.contains(&"warm.mkv".to_string()), "{names:?}");
    assert!(names.contains(&"cold.mkv".to_string()), "{names:?}");
    engine.close().unwrap();
}

/// Both volumes present ONE tree — a cold title and a warm title side by side
/// under the same `Movies` folder. This is what "one cohesive location" means.
#[test]
fn the_two_roots_merge_into_one_tree() {
    let dir = tempfile::tempdir().unwrap();
    let (warm, cold) = two_volumes(dir.path());
    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&warm)).unwrap();
    engine.bind_folder(&m, spec(&cold)).unwrap();
    engine.scan(Some(&m)).unwrap();

    let movies = engine
        .children(&m)
        .unwrap()
        .into_iter()
        .find(|c| c.label == "Movies")
        .expect("one Movies folder, not one per volume");
    let titles: Vec<String> = engine
        .children(&movies.node.id)
        .unwrap()
        .into_iter()
        .map(|c| c.label)
        .collect();
    assert_eq!(titles.len(), 2, "both titles under one Movies: {titles:?}");
    engine.close().unwrap();
}

/// Unbinding one root leaves the other, and the files it holds.
#[test]
fn unbinding_one_root_leaves_the_other() {
    let dir = tempfile::tempdir().unwrap();
    let (warm, cold) = two_volumes(dir.path());
    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&warm)).unwrap();
    engine.bind_folder(&m, spec(&cold)).unwrap();
    engine.scan(Some(&m)).unwrap();

    let cold_uri = format!("file://{}", cold.display());
    engine.unbind_folder(&m, Some(&cold_uri)).unwrap();

    let left = engine.bindings_for(&m).unwrap();
    assert_eq!(left.len(), 1, "one root removed, one kept");
    assert!(left[0].source_uri.contains("Data"), "{:?}", left[0].source_uri);
    engine.close().unwrap();
}

/// "Unbind the folder" must not silently mean "detach every volume".
#[test]
fn unbinding_without_naming_a_root_is_refused_when_there_are_several() {
    let dir = tempfile::tempdir().unwrap();
    let (warm, cold) = two_volumes(dir.path());
    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&warm)).unwrap();
    engine.bind_folder(&m, spec(&cold)).unwrap();

    let err = engine.unbind_folder(&m, None).unwrap_err().to_string();
    assert!(err.contains("2 roots"), "it must say how many, and which: {err}");
    assert_eq!(
        engine.bindings_for(&m).unwrap().len(),
        2,
        "and change nothing"
    );

    // With one root, no answer is needed — the question has one answer.
    let warm_uri = format!("file://{}", warm.display());
    engine.unbind_folder(&m, Some(&warm_uri)).unwrap();
    engine.unbind_folder(&m, None).unwrap();
    assert!(engine.bindings_for(&m).unwrap().is_empty());
    engine.close().unwrap();
}


/// A REPLICA's roots are all LOCAL, and all of them must be listed and scanned.
///
/// Found by the distributed lab run, invisible to every single-box test before
/// it. An owner's bindings are LOGGED and come from the projection; a replica's
/// live in `.pvfs/bindings.local`. The merge that folds local rows in compared
/// FOLDER only, so the first local root shadowed every later one: a two-root
/// replica listed one, and `local_bindings` — which the scan walks — returned
/// one. Chris's NAS would have scanned `Data` and silently ignored `Data_ext`.
///
/// This writes `bindings.local` DIRECTLY, because that is the only way to
/// exercise the path: `bind_folder` on an owner takes the logged route and
/// never touches the merge at all. My first attempt at this test used an owner
/// and passed with the fix reverted — it was testing the wrong half.
#[test]
fn every_local_root_of_a_folder_is_listed_and_scannable() {
    let dir = tempfile::tempdir().unwrap();
    let (warm, cold) = two_volumes(dir.path());
    let forest = dir.path().join("forest");
    let (mut engine, _mn) = Engine::init(forest.as_path()).unwrap();
    let m = media(&mut engine);
    let data_dir = engine.data_dir().to_path_buf();
    engine.close().unwrap();

    // Two LOCAL roots for one folder, as a replica records them.
    std::fs::write(
        data_dir.join("bindings.local"),
        format!(
            "pvfs-local-bindings 1\n\
             bind {m} 1 1 lazy 1000 - file://{}\n\
             bind {m} 1 1 lazy 1001 - file://{}\n",
            warm.display(),
            cold.display()
        ),
    )
    .unwrap();

    let engine = Engine::open(&data_dir).unwrap();
    assert_eq!(
        engine.bindings().unwrap().len(),
        2,
        "both local roots must be listed, not just the first"
    );
    assert_eq!(
        engine.local_bindings().unwrap().len(),
        2,
        "the scan walks `local_bindings`; dropping one here loses half a library"
    );
    assert_eq!(
        engine.bindings_for(&m).unwrap().len(),
        2,
        "and the mover's view must agree with the operator's"
    );
    engine.close().unwrap();
}
