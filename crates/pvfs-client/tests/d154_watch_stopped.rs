//! D154 — a stopped pass is not reported as ingested.
//!
//! The watch sent `Ingested` for every report of a pass, stopped or not, and
//! the daemon logged `watch ingested … +8520` for a mediabox pass that had
//! committed nothing, one second before it shut down. A stopped pass is now
//! `Stopped`: never `Ingested`, and never `Quiet`, which means a completed
//! pass.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use pvfs_client::watch::{self, WatchEvent};
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

#[test]
fn a_stopped_pass_is_stopped_not_ingested_and_not_quiet() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    for i in 0..3u8 {
        std::fs::write(lib.join(format!("e{i}.mkv")), vec![i; 64]).unwrap();
    }
    let data = dir.path().join("forest");
    let region = {
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
        region
    };

    // The stop is already raised when the watch starts, as when SIGTERM lands
    // during its first pass. The files were written just now, so they are
    // inside the watch's settle window and the pass has none to take; the
    // stop ends it before its sweep and its head.
    let stop = Arc::new(AtomicBool::new(true));
    let mut seen: Vec<String> = Vec::new();
    watch::run(&data, 3600, 2000, 30_000, &stop, |ev| {
        seen.push(match ev {
            WatchEvent::Ingested(f, ..) => format!("ingested {f}"),
            WatchEvent::Stopped(f, a, c, _) => format!("stopped {f} +{a} !{c}"),
            WatchEvent::Quiet => "quiet".into(),
            WatchEvent::PassStarted => "started".into(),
            WatchEvent::ScanError(e) => format!("error {e}"),
            WatchEvent::Watching(..) => "watching".into(),
            WatchEvent::NeedsAttention(n, _) => format!("attention {n}"),
        })
    })
    .unwrap();

    assert!(seen.contains(&format!("stopped {region} +0 !0")), "{seen:?}");
    assert!(
        !seen.iter().any(|s| s.starts_with("ingested") || s == "quiet"),
        "a stopped pass is neither an ingest nor a completed quiet pass: {seen:?}"
    );

    // And nothing was published for it.
    let e = Engine::open(&data).unwrap();
    assert!(e.region_snapshots(&region).unwrap().is_empty(), "{seen:?}");
}
