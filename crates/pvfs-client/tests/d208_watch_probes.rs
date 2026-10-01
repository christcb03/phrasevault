//! PVOS D208 — the daemon's watch (`watch::run_shared`) measures video
//! quality with the prober this box has: `PVFS_FFPROBE` names a stand-in
//! here (the test server has no ffprobe), and the rows it catalogues get
//! the measurement, a non-video file none. One test in its own process: it
//! sets the environment.

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, SharedDb, Writer, TYPE_FOLDER};

const FAKE: &str = r#"#!/bin/sh
for a; do f="$a"; done
[ "$f" = "-version" ] && { echo "ffprobe version stand-in"; exit 0; }
echo "$f" >> "$(dirname "$0")/probed.log"
echo "codec_name=h264"
echo "width=1280"
echo "height=720"
echo "duration=600.0"
echo "size=1000"
"#;

#[test]
fn the_daemons_watch_measures_what_it_catalogues() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let script = bin.join("ffprobe");
    std::fs::write(&script, FAKE).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::env::set_var("PVFS_FFPROBE", &script);

    let (mut e, _) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let media = tmp.path().join("media");
    std::fs::create_dir_all(media.join("Show")).unwrap();
    std::fs::write(media.join("Show/e01.mkv"), "episode one").unwrap();
    std::fs::write(media.join("Show/e01.nfo"), "<episode/>").unwrap();
    let root = e.identity.root_node_id.clone();
    let region = e
        .add_node(
            &root,
            NodeSpec { node_type: TYPE_FOLDER.into(), label: "Local".into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
        )
        .unwrap();
    e.region_mark_as(&region, "catalogue", None).unwrap();
    e.bind_folder(
        &region,
        BindSpec {
            source_uri: format!("file://{}", media.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();

    let writer = Arc::new(Writer::new(e));
    let stop = Arc::new(AtomicBool::new(false));
    let watch = {
        let (w, stop) = (Arc::clone(&writer), Arc::clone(&stop));
        std::thread::spawn(move || pvfs_client::watch::run_shared(w, 3600, 200, 2000, &stop, |_| {}))
    };
    let db = SharedDb::new(Arc::clone(&writer), "test").unwrap();
    let quality = |rel: &str| -> Option<Option<String>> {
        db.read_rows(&region).into_iter().find(|r| r.rel_path == rel).map(|r| r.quality)
    };
    // The files settle (15 s) before a pass takes them.
    let t = Instant::now();
    while quality("Show/e01.mkv").flatten().is_none() {
        assert!(t.elapsed() < Duration::from_secs(90), "the watch never measured e01.mkv");
        std::thread::sleep(Duration::from_millis(200));
    }
    stop.store(true, Ordering::SeqCst);
    watch.join().unwrap().unwrap();
    let q = pvfs_core::media::MediaQuality::decode(&quality("Show/e01.mkv").flatten().unwrap()).unwrap();
    assert_eq!((q.width, q.height, q.duration_s, q.video_codec.as_str()), (1280, 720, 600, "h264"));
    assert_eq!(quality("Show/e01.nfo"), Some(None), "catalogued, never probed");
    let asked = std::fs::read_to_string(bin.join("probed.log")).unwrap();
    assert_eq!(asked.lines().count(), 1, "{asked}");
}

trait Rows {
    fn read_rows(&self, region: &str) -> Vec<pvfs_core::RegionEntry>;
}

impl Rows for SharedDb {
    fn read_rows(&self, region: &str) -> Vec<pvfs_core::RegionEntry> {
        use pvfs_core::writer::Db;
        self.read(|e| e.region_entries(&region.to_string())).unwrap()
    }
}
