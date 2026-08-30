//! D83 — the mover must be interruptible, because serving reads outranks it.
//!
//! Chris, 2026-08-24: *"having the daemon serving files and allowing reads to
//! the library is the #1 top priority... Killing background transfers isn't a
//! very big issue, not serving files would be."*
//!
//! What went wrong: `spawn_pass` created a stop flag and never gave it to the
//! pass — "passes are short". True of sync/evict/reclaim, false of `tier`,
//! which moves hundreds of GB over a WAN. A signalled daemon closed both
//! listeners and then waited the better part of an hour for a 14.7GB fetch,
//! answering nothing. Every file held only by that box read as
//! `available location not found`.
//!
//! So the mover has to be able to STOP, and stopping is not an error.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pvfs_client::fetch::Fetcher;
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

/// A library with a central store to migrate into — the shape a tier pass runs
/// against.
fn library(dir: &std::path::Path, n: usize) -> (Engine, String, std::path::PathBuf) {
    let src = dir.join("staging").join("Media");
    std::fs::create_dir_all(&src).unwrap();
    for i in 1..=n {
        std::fs::write(src.join(format!("ep{i:02}.mkv")), vec![b'a' + i as u8; 2048 + i]).unwrap();
    }
    let central = dir.join("central").join("Media");
    std::fs::create_dir_all(&central).unwrap();

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
    let sp = spec(&src);
    let uri = sp.source_uri.clone();
    engine.scan_unbound(&media, &uri, &sp, &mut None, 0).unwrap();
    (engine, media, central)
}

/// A fetcher with no flag behaves exactly as before — cancellation is opt-in,
/// so nothing that does not ask for it can be stopped by accident.
#[test]
fn a_fetcher_without_a_flag_is_never_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fetcher::new(dir.path());
    assert!(!f.cancelled(), "no flag means never cancelled");
}

/// The flag is observed through the fetcher, which is how the daemon hands the
/// job's stop flag to the mover.
#[test]
fn a_raised_flag_is_visible_to_the_mover() {
    let dir = tempfile::tempdir().unwrap();
    let mut f = Fetcher::new(dir.path());
    let flag = Arc::new(AtomicBool::new(false));
    f.set_cancel(Arc::clone(&flag));

    assert!(!f.cancelled(), "not cancelled until the flag is raised");
    flag.store(true, Ordering::SeqCst);
    assert!(f.cancelled(), "the mover must see the daemon's stop flag");
}

/// THE POINT: a pass told to stop before it starts must stop, and must NOT
/// report an error. A mover that was asked to stop has not failed — reporting
/// it as failure would stamp a permanent `last_error` on the job every time
/// the daemon restarts, and that is how a real fault gets lost in noise.
#[test]
fn a_cancelled_pass_stops_and_is_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, media, central) = library(dir.path(), 6);
    let fid = engine.identity.forest_id.clone();
    let dd = engine.data_dir().to_path_buf();
    pvfs_core::sync::write_central_marker(&central, &fid).unwrap();
    pvfs_core::sync::set_central(&dd, &media, &central, false).unwrap();
    pvfs_core::sync::set_central_tree(&dd, &media, true).unwrap();

    let mut fetcher = Fetcher::new(engine.data_dir());
    let flag = Arc::new(AtomicBool::new(true)); // already cancelled
    fetcher.set_cancel(flag);

    let out = pvfs_client::fetch::tier_pass(&mut engine, &mut fetcher);
    assert!(
        out.is_ok(),
        "a cancelled pass is not a failure — it reports what it did: {out:?}"
    );
    if let Ok(Some(report)) = out {
        assert_eq!(
            report.migrated, 0,
            "cancelled before the first file, so nothing should have moved"
        );
        // The return value being Ok was never enough. Cancelling mid-pass
        // abandons every in-flight fetch, and each abandoned migration lands
        // in `failed` looking exactly like a real one — which the daemon then
        // stamps as the job's last_error. In production that turned an orderly
        // stop into "215 migrations failed" when 34 were real. The pass has to
        // SAY it was cancelled so the daemon can withhold the verdict.
        assert!(
            report.cancelled,
            "a cancelled pass must mark itself cancelled, or its abandoned \
             work is reported as failure"
        );
    }
    engine.close().unwrap();
}
