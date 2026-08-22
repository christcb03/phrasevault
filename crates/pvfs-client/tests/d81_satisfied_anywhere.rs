//! D81 4b — a file already in the library is not work.
//!
//! Chris: "I need it to be able to understand when I move things from Data to
//! data_ext manually. It needs to be able to update the location to the new
//! place without trying to move it again."
//!
//! The first half already worked — the scan records the new location (D71 W6
//! `relocated`). The second half did not: `has_central` asked only whether a
//! copy sat at the WRITE TARGET, so the very next mover pass saw the title
//! missing from `Data` and fetched it back. The catalog knew exactly where the
//! file was; the mover was asking the wrong question.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::Lazy,
    }
}

fn count_files(dir: &std::path::Path) -> usize {
    fn walk(d: &std::path::Path, n: &mut usize) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, n);
                } else if p.file_name().and_then(|s| s.to_str()) != Some(".pvfs-central") {
                    *n += 1;
                }
            }
        }
    }
    let mut n = 0;
    walk(dir, &mut n);
    n
}

/// Chris's workflow, end to end: hand-move a title to the cold volume and the
/// mover must leave it there.
#[test]
fn a_title_hand_moved_to_the_cold_volume_is_not_fetched_back() {
    let tmp = tempfile::tempdir().unwrap();
    let warm = tmp.path().join("Data");        // the write target
    let cold = tmp.path().join("Data_ext");    // where Chris files cold titles
    let rel = "Movies/Cold Title (1998)/cold.mkv";
    std::fs::create_dir_all(warm.join("Movies/Cold Title (1998)")).unwrap();
    std::fs::create_dir_all(cold.join("Movies/Cold Title (1998)")).unwrap();
    std::fs::write(warm.join(rel), vec![4u8; 6000]).unwrap();

    let (mut engine, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
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
    // Both volumes are roots of the one library (4a).
    engine.bind_folder(&media, spec(&warm)).unwrap();
    engine.bind_folder(&media, spec(&cold)).unwrap();
    engine.scan_routed(Some(&media), None, 0).unwrap();

    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_central(&data_dir, &media, &warm, true).unwrap();
    pvfs_core::sync::set_central_tree(&data_dir, &media, true).unwrap();

    // Chris moves it, by hand, exactly as he does on the NAS.
    std::fs::rename(warm.join(rel), cold.join(rel)).unwrap();
    engine.scan_routed(Some(&media), None, 0).unwrap();

    let locs = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .find(|e| e.node.node_type == pvfs_core::TYPE_FILE)
        .map(|e| engine.locations(&e.node.id).unwrap())
        .unwrap_or_default();
    assert!(
        locs.iter().any(|u| u.contains("Data_ext")),
        "the scan must record where it actually is: {locs:?}"
    );
    assert!(
        !locs.iter().any(|u| u.contains("/Data/")),
        "and must not still claim the old place: {locs:?}"
    );

    // THE POINT: a mover pass must plan nothing for it.
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    let report = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, true)
        .unwrap()
        .expect("a central placement exists");
    assert!(
        report.planned.is_empty(),
        "the title is in the library, on the cold volume, exactly where Chris \
         put it — planning ANY work here is the mover undoing a deliberate \
         filing decision: {:?}",
        report.planned
    );
    assert_eq!(report.satisfied, 1, "satisfied where it lies");
    assert_eq!(
        count_files(&cold),
        1,
        "and it is still on the cold volume afterwards"
    );
    assert_eq!(count_files(&warm), 0, "not copied back to the warm one");
    engine.close().unwrap();
}

/// The write target is still the ONE place new content goes.
///
/// "Satisfied anywhere" must not become "place anywhere": a file that is in the
/// library nowhere at all still belongs at the write target, and only there.
#[test]
fn new_content_still_goes_to_the_write_target_only() {
    let tmp = tempfile::tempdir().unwrap();
    let warm = tmp.path().join("Data");
    let cold = tmp.path().join("Data_ext");
    let staging = tmp.path().join("incoming");
    std::fs::create_dir_all(warm.join("Movies")).unwrap();
    std::fs::create_dir_all(cold.join("Movies")).unwrap();
    std::fs::create_dir_all(staging.join("Movies/New Title (2026)")).unwrap();
    std::fs::write(
        staging.join("Movies/New Title (2026)/new.mkv"),
        vec![5u8; 7000],
    )
    .unwrap();

    let (mut engine, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
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
    engine.bind_folder(&media, spec(&staging)).unwrap();
    engine.bind_folder(&media, spec(&cold)).unwrap();
    engine.scan_routed(Some(&media), None, 0).unwrap();

    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_central(&data_dir, &media, &warm, false).unwrap();
    pvfs_core::sync::set_central_tree(&data_dir, &media, true).unwrap();

    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, false)
        .unwrap()
        .expect("a central placement exists");

    assert_eq!(
        count_files(&warm),
        1,
        "new content lands at the write target"
    );
    assert_eq!(
        count_files(&cold),
        0,
        "and NOT on the other root just because it is also a library root"
    );
    engine.close().unwrap();
}
