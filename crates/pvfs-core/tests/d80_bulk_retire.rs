//! D80 §8 — the bulk retire path.
//!
//! The migration's last step worked in the lab, but at 3.2 removals/sec: one
//! process spawn and one fsync per file. That rate, not the risk, is what made
//! retiring 27,565 locations an overnight job. `retire_locations_under` emits
//! the SAME events and batches the appends.
//!
//! Speed is the reason it exists; the refusal is the reason it is safe. A
//! location is removed only while its file keeps another live one, so the
//! failure mode of the drain that stranded 26,729 files — retire first, look
//! later — is not reachable from here even when the run is interrupted.

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

fn library(root: &std::path::Path, n: usize) -> std::path::PathBuf {
    let media = root.join("Media");
    let season = media.join("TV").join("Show (2015)").join("Season 01");
    std::fs::create_dir_all(&season).unwrap();
    for i in 1..=n {
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

/// Production's shape after the holder's scan: every file has the owner's NFS
/// view AND the holder's own path. Returns the engine, the folder, and the
/// prefix that is about to be retired.
fn migrated(dir: &std::path::Path, n: usize) -> (Engine, String, String) {
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
    engine.scan_unbound(&media, &uri, &sp, &mut None, 0).unwrap();

    // The holder's scan — no new nodes, a second location each.
    let sp2 = spec(&nas);
    let uri2 = sp2.source_uri.clone();
    let stats = engine.scan_unbound(&media, &uri2, &sp2, &mut None, 0).unwrap();
    assert_eq!(stats.added, 0, "the holder holds the same library");
    assert_eq!(stats.relocated as usize, n);

    let prefix = format!("file://{}/", nfs.display());
    (engine, media, prefix)
}

/// The whole safety property, in one test: what is held elsewhere goes, and
/// what is held nowhere else is REFUSED — not removed and reported, not removed
/// silently. Refusing is the behaviour that makes an interrupted run harmless.
#[test]
fn it_retires_what_is_held_elsewhere_and_refuses_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, prefix) = migrated(dir.path(), 6);
    let files = files_under(&engine, &media);

    // One file the holder never got — its NFS location is the only record of
    // it. This is the production 177: stale entries and ambiguous matches.
    let orphan = files[2].clone();
    let holder_uri = engine
        .locations(&orphan)
        .unwrap()
        .into_iter()
        .find(|u| !u.starts_with(&prefix))
        .expect("it has a holder location to take away");
    engine.remove_location(&orphan, &holder_uri).unwrap();

    let report = engine.retire_locations_under(&prefix, false, 500).unwrap();

    assert_eq!(report.eligible, 5, "five files are held by the holder too");
    assert_eq!(report.removed, 5);
    assert_eq!(report.refused.len(), 1, "the one held nowhere else is refused");
    assert_eq!(report.refused[0].0, orphan);

    for f in &files {
        let locs = engine.locations(f).unwrap();
        assert!(!locs.is_empty(), "no file may be left held by nobody");
        if *f == orphan {
            assert_eq!(locs.len(), 1);
            assert!(locs[0].starts_with(&prefix), "the refused location is still there");
        } else {
            assert!(
                locs.iter().all(|u| !u.starts_with(&prefix)),
                "the retired view is gone from every file that had a copy"
            );
        }
    }
    engine.close().unwrap();
}

/// A dry run has to be worth trusting before a 27,565-location run: it must
/// report the same counts and change nothing at all.
#[test]
fn a_dry_run_counts_everything_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, prefix) = migrated(dir.path(), 4);
    let files = files_under(&engine, &media);
    let before: Vec<Vec<String>> = files.iter().map(|f| engine.locations(f).unwrap()).collect();

    let report = engine.retire_locations_under(&prefix, true, 500).unwrap();
    assert_eq!(report.eligible, 4);
    assert_eq!(report.removed, 0, "a dry run removes nothing");

    let after: Vec<Vec<String>> = files.iter().map(|f| engine.locations(f).unwrap()).collect();
    assert_eq!(before, after, "and leaves every location exactly as it was");
    engine.close().unwrap();
}

/// The batch size is a performance knob, so it must not be able to change the
/// result — including at 1, which is the per-file behaviour the lab measured.
#[test]
fn the_batch_size_does_not_change_the_outcome() {
    for batch in [1usize, 3, 500] {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, media, prefix) = migrated(dir.path(), 5);
        let report = engine.retire_locations_under(&prefix, false, batch).unwrap();
        assert_eq!(report.removed, 5, "batch {batch} retires the same five");
        assert!(report.refused.is_empty());
        for f in files_under(&engine, &media) {
            let locs = engine.locations(&f).unwrap();
            assert_eq!(locs.len(), 1, "batch {batch}: one location left");
            assert!(!locs[0].starts_with(&prefix));
        }
        engine.close().unwrap();
    }
}

/// Running it twice must be a no-op the second time — the migration will be
/// re-run after a partial pass, and re-running must not error or double-remove.
#[test]
fn a_second_run_finds_nothing_left_to_do() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _media, prefix) = migrated(dir.path(), 4);

    let first = engine.retire_locations_under(&prefix, false, 500).unwrap();
    assert_eq!(first.removed, 4);

    let second = engine.retire_locations_under(&prefix, false, 500).unwrap();
    assert_eq!(second.eligible, 0, "nothing under the prefix is live any more");
    assert_eq!(second.removed, 0);
    assert!(second.refused.is_empty());
    engine.close().unwrap();
}
