//! A pass must be stoppable in the middle, not only between passes.
//!
//! `watch::run` checked its stop flag at the top of the loop, so once
//! `scan_pass` was entered it ran the whole library — walking every directory
//! and hashing every unhashed file. SIGTERM sets that flag, and the daemon's
//! drain then waits for the job thread to join, so the process could not exit
//! until the pass finished.
//!
//! On the NAS holder that meant SIGTERM was ignored for a quarter of an hour
//! and counting, the binary swap refused to proceed (correctly — it will not
//! half-swap a running daemon), and the box could not be rolled at all. One
//! film there is 7.7 GB, so even checking between FILES is too coarse; the
//! hasher checks per 1 MiB read.
//!
//! Abandoning a pass is safe because the scan is resumable by construction:
//! `scan_state` records progress per file, so the next pass continues.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::OnAdd,
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

/// A small library: enough files that a full pass is visibly different from a
/// stopped one.
fn library(root: &std::path::Path) -> std::path::PathBuf {
    let lib = root.join("library");
    for i in 0..6 {
        let d = lib.join(format!("Title {i} (20{i}0)"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("film{i}.mkv")), vec![i as u8; 4096]).unwrap();
    }
    lib
}

#[test]
fn a_stop_is_honoured_inside_a_pass() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&lib)).unwrap();

    let stop = Arc::new(AtomicBool::new(true));
    engine.set_cancel(Arc::clone(&stop));

    let reports = engine.scan(Some(&m)).unwrap();
    assert!(
        reports[0].stats.cancelled,
        "the pass says it stopped rather than reporting a clean sweep of nothing"
    );
    assert_eq!(
        reports[0].stats.added, 0,
        "a pass told to stop before it began ingests nothing"
    );
    engine.close().unwrap();
}

/// The property that makes stopping safe at all.
#[test]
fn a_stopped_pass_resumes_on_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&lib)).unwrap();

    let stop = Arc::new(AtomicBool::new(true));
    engine.set_cancel(Arc::clone(&stop));
    engine.scan(Some(&m)).unwrap();

    // Let it go, and the very next pass catalogues the library in full.
    stop.store(false, Ordering::SeqCst);
    let reports = engine.scan(Some(&m)).unwrap();
    assert!(!reports[0].stats.cancelled);
    assert_eq!(reports[0].stats.added, 6, "all six films, nothing skipped");

    let movies: Vec<String> = engine
        .children(&m)
        .unwrap()
        .into_iter()
        .map(|c| c.label)
        .collect();
    assert_eq!(movies.len(), 6, "and the tree has them: {movies:?}");
    engine.close().unwrap();
}

/// Without a flag the engine is never cancelled — the default must not make
/// every pass stoppable-by-accident.
#[test]
fn an_engine_with_no_flag_runs_to_completion() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&lib)).unwrap();

    assert!(!engine.cancelled());
    let reports = engine.scan(Some(&m)).unwrap();
    assert!(!reports[0].stats.cancelled);
    assert_eq!(reports[0].stats.added, 6);
    engine.close().unwrap();
}

/// The hasher is where the time actually goes, so it checks too.
#[test]
fn the_hasher_stops_mid_file() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("big.mkv");
    // Several read buffers' worth, so there is more than one check to hit.
    std::fs::write(&f, vec![7u8; 4 << 20]).unwrap();

    let go = AtomicBool::new(false);
    let hashed = pvfs_core::sync::hash_with_manifest_until(&f, Some(&go)).unwrap();
    assert!(hashed.is_some(), "not asked to stop, so it hashes");

    let stop = AtomicBool::new(true);
    let abandoned = pvfs_core::sync::hash_with_manifest_until(&f, Some(&stop)).unwrap();
    assert!(
        abandoned.is_none(),
        "asked to stop, it abandons the read rather than finishing 7.7 GB first"
    );

    // And the plain entry point is unchanged for every other caller.
    let (h, chunks) = pvfs_core::sync::hash_with_manifest(&f).unwrap();
    assert_eq!(h.len(), 64);
    assert!(!chunks.is_empty());
}
