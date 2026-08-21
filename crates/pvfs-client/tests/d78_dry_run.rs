//! D76/D78 — plan every action, take none of them.
//!
//! Two bugs in this milestone were only visible in what the mover had already
//! DONE: locations retired that should not have been, and bytes written to a
//! disk that was not the NAS. A dry run is the cheapest defence against the
//! next one — but only if it genuinely writes nothing, which is what this
//! asserts by diffing the store rather than trusting the output.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

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

/// The core promise: a dry run plans real work and changes nothing.
#[test]
fn a_dry_run_plans_the_work_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("local");
    let store = tmp.path().join("store");
    std::fs::create_dir_all(src.join("TV").join("Show").join("Season 01")).unwrap();
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(src.join("TV/Show/Season 01/ep.mkv"), vec![3u8; 8192]).unwrap();

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
    engine
        .bind_folder(
            &media,
            BindSpec {
                source_uri: format!("file://{}", src.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::Lazy,
            },
        )
        .unwrap();
    engine.scan_routed(Some(&media), None, 0).unwrap();

    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_central(&data_dir, &media, &store, false).unwrap();
    pvfs_core::sync::set_central_tree(&data_dir, &media, true).unwrap();

    let before = count_files(&store);
    assert_eq!(before, 0, "store starts empty");

    // DRY RUN
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    let report = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, true)
        .unwrap()
        .expect("something is placed central");

    assert!(
        !report.planned.is_empty(),
        "a dry run with real work must PLAN something, not silently do nothing"
    );
    assert!(
        report.planned.iter().any(|p| p.contains("WOULD")),
        "the plan must say what it WOULD do: {:?}",
        report.planned
    );
    assert_eq!(
        count_files(&store),
        before,
        "THE WHOLE POINT: a dry run writes nothing. The store must be untouched."
    );

    // ...and now for real, to prove the plan described reality.
    let real = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, false)
        .unwrap()
        .unwrap();
    assert!(
        real.planned.is_empty(),
        "a REAL pass plans nothing — `planned` is dry-run-only"
    );
    assert_eq!(
        count_files(&store),
        1,
        "the real pass placed the file the dry run predicted"
    );
    assert_eq!(
        real.migrated, report.migrated,
        "the plan's count matched what actually happened"
    );
    engine.close().unwrap();
}

/// A dry run on a settled fleet plans nothing and still writes nothing — the
/// idle case, which must not report phantom work.
#[test]
fn a_dry_run_on_settled_state_plans_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("store");
    std::fs::create_dir_all(&store).unwrap();

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
    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_central(&data_dir, &media, &store, false).unwrap();
    pvfs_core::sync::set_central_tree(&data_dir, &media, true).unwrap();

    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    let report = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, true)
        .unwrap()
        .unwrap();
    assert!(report.planned.is_empty(), "nothing to do ⇒ nothing planned");
    assert_eq!(report.migrated, 0);
    assert_eq!(count_files(&store), 0);
    engine.close().unwrap();
}
