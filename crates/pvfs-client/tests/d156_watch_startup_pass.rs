//! D156 — the watch's startup pass reports the way every other pass does.
//!
//! `watch::run` makes one pass before it starts watching, and that pass had
//! its own copy of the report-to-event loop: `Ingested` for every report,
//! never `Quiet`, and so never D156's `NeedsAttention`. The lab found it: the
//! first pass after the D156 roll skipped a file with a real EIO and said
//! nothing about it, while every later pass did. Both now go through
//! `pass_events`, whose unit tests cover the quarantine. This test pins the
//! startup pass to it: a clean startup pass is `Quiet`, as a clean pass
//! anywhere else is, where the old copy said `Ingested` of nothing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pvfs_client::watch::{self, WatchEvent};
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

#[test]
fn the_startup_pass_reports_like_every_other_pass() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    // Written just now, so inside the watch's settle window: the pass has
    // nothing to take, and completes with nothing to say.
    std::fs::write(lib.join("e0.mkv"), b"fresh").unwrap();
    let data = dir.path().join("forest");
    {
        let (mut e, _mn) = Engine::init(&data).unwrap();
        let root = e.identity.root_node_id.clone();
        let region = e
            .add_node(
                &root,
                NodeSpec {
                    node_type: TYPE_FOLDER.into(),
                    label: "Library".into(),
                    payload: Vec::new(),
                    is_temp: false,
                    creation_nonce: None,
                },
            )
            .unwrap();
        e.region_mark_as(&region, "catalogue", None).unwrap();
        e.bind_folder(
            &region,
            BindSpec {
                source_uri: format!("file://{}", lib.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
        e.close().unwrap();
    }

    let stop = Arc::new(AtomicBool::new(false));
    let mut seen: Vec<String> = Vec::new();
    watch::run(&data, 3600, 2000, 30_000, &stop, |ev| {
        seen.push(match ev {
            WatchEvent::Ingested(..) => "ingested".into(),
            WatchEvent::Stopped(..) => "stopped".into(),
            WatchEvent::Quiet => "quiet".into(),
            WatchEvent::PassStarted => "started".into(),
            WatchEvent::ScanError(e) => format!("error {e}"),
            WatchEvent::NeedsAttention(n, _) => format!("attention {n}"),
            WatchEvent::Watching(..) => {
                // The startup pass is over, which is all this test is about.
                stop.store(true, Ordering::SeqCst);
                "watching".into()
            }
        })
    })
    .unwrap();

    assert_eq!(seen, vec!["started", "quiet", "watching"], "{seen:?}");
}
