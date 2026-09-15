//! D152 — a file dated in the future is judged by its ctime.
//!
//! The settle window (D71 W6) defers a file while `changed_ms + settle > now`,
//! and D112 made `changed_ms` `max(mtime, ctime)` because rclone back-dates
//! mtime. A file some other tool stamped 2038-01-18 (2³¹−1) was then "still
//! settling" on every pass until 2038: never hashed, never catalogued — 164
//! such files on mediabox, 2026-09-14 — and the watch re-ran every 20 s for
//! them. A stamp that far ahead is now left out, so the ctime judges.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

/// A settle window short enough to wait out in a test. The rule does not
/// depend on its length.
const SETTLE_MS: u64 = 1_500;

/// 2³¹−1 seconds: 2038-01-19 03:14:07 UTC, the stamp on 161 of mediabox's
/// files.
fn y2038() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(2_147_483_647)
}

/// Stamp `p`'s mtime. The kernel sets its ctime to now on the same call —
/// the property the rule leans on, as it does on mediabox.
fn set_mtime(p: &Path, t: SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

fn mtime(p: &Path) -> SystemTime {
    std::fs::metadata(p).unwrap().modified().unwrap()
}

/// Wait out the window for everything stamped before this call.
fn let_it_settle() {
    std::thread::sleep(Duration::from_millis(SETTLE_MS + 500));
}

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec {
            node_type: TYPE_FOLDER.into(),
            label: label.into(),
            payload: Vec::new(),
            is_temp: false,
            creation_nonce: None,
        },
    )
    .unwrap()
}

fn bind(e: &mut Engine, folder: &str, lib: &Path) {
    e.bind_folder(
        &folder.to_string(),
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
}

/// A forest whose `Media` folder is bound to `<dir>/lib`.
fn forest(dir: &Path) -> (Engine, String, std::path::PathBuf) {
    let lib = dir.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    let (mut e, _mn) = Engine::init(&dir.join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();
    let media = folder(&mut e, &root, "Media");
    bind(&mut e, &media, &lib);
    (e, media, lib)
}

fn scan(e: &mut Engine, folder: &str) -> pvfs_core::ScanStats {
    e.scan_routed(Some(&folder.to_string()), None, SETTLE_MS)
        .unwrap()
        .remove(0)
        .stats
}

fn file_names(e: &Engine, folder: &str) -> Vec<String> {
    e.children(&folder.to_string())
        .unwrap()
        .into_iter()
        .filter(|c| c.node.node_type == TYPE_FILE)
        .map(|c| c.label)
        .collect()
}

/// The regression: a file dated 2038 whose stamp has stopped moving is
/// catalogued, instead of settling on every pass until 2038.
#[test]
fn a_file_dated_2038_is_catalogued_once_its_ctime_settles() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, media, lib) = forest(dir.path());
    let name = "The Big Bang Theory - s11e01 - The Proposal Proposal.mkv";
    let f = lib.join(name);
    std::fs::write(&f, vec![7u8; 4096]).unwrap();
    set_mtime(&f, y2038());

    // Stamped a moment ago: it JUST changed, and the window still holds.
    let s = scan(&mut e, &media);
    assert_eq!((s.added, s.settling), (0, 1), "a fresh ctime is still deferred");

    let_it_settle();
    let s = scan(&mut e, &media);
    assert_eq!(
        s.settling, 0,
        "before D152 this was 1 on every pass until 2038, and the watch re-ran \
         every 20 s for it"
    );
    assert_eq!(s.added, 1);
    assert_eq!(file_names(&e, &media), vec![name]);

    // D150: its sidecar is dated no earlier than the file, so it is trusted
    // and the next pass has nothing to do.
    let side = pvfs_core::sync::manifest_sidecar_path(&f);
    assert!(mtime(&side) >= y2038(), "the sidecar is dated with its file (D150)");
    let s = scan(&mut e, &media);
    assert_eq!((s.added, s.changed, s.settling), (0, 0, 0));
    e.close().unwrap();
}

/// The same through a catalogue region's scan, which is how mediabox's two
/// disks are catalogued (D147): the file gets a row, with its hash.
#[test]
fn a_catalogue_region_gets_a_row_for_a_file_dated_2038() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(lib.join("TV")).unwrap();
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = folder(&mut e, &root, "Library");
    e.region_mark_as(&region, "catalogue", None).unwrap();
    bind(&mut e, &region, &lib);
    let rel = "TV/Doctor Who - s10e01.mkv";
    let f = lib.join(rel);
    std::fs::write(&f, vec![3u8; 3000]).unwrap();
    set_mtime(&f, y2038());
    let row = |e: &Engine| {
        e.region_entries(&region)
            .unwrap()
            .into_iter()
            .find(|r| r.rel_path == rel)
    };

    let s = scan(&mut e, &region);
    assert_eq!(s.settling, 1);
    assert!(row(&e).is_none(), "no row while its ctime is inside the window");

    let_it_settle();
    let s = scan(&mut e, &region);
    assert_eq!((s.added, s.settling), (1, 0));
    let r = row(&e).expect("a row once it has settled");
    assert_eq!(r.size_bytes, 3000);
    assert!(r.content_hash.is_some(), "hashed, as on_add says");
    assert_eq!(r.mtime_ms, 2_147_483_647_000, "the row keeps the mtime as it is");
    assert!(
        r.changed_ms < 2_147_483_647_000,
        "and its settle signal is the ctime, not 2038"
    );

    let s = scan(&mut e, &region);
    assert_eq!((s.unchanged, s.settling), (1, 0), "the next pass is quiet");
    e.close().unwrap();
}

/// Not weakened: a stamp just ahead of this clock is skew between boxes (the
/// NAS runs 142 s slow, D150), and is believed — the file settles once the
/// clock passes it, not at once.
#[test]
fn a_stamp_just_ahead_of_the_clock_is_still_honoured() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, media, lib) = forest(dir.path());
    let f = lib.join("President Curtis - s01e08.mkv");
    std::fs::write(&f, vec![5u8; 2048]).unwrap();
    set_mtime(&f, SystemTime::now() + Duration::from_secs(142));

    let_it_settle(); // its ctime is out of the window…
    let s = scan(&mut e, &media);
    assert_eq!(
        (s.added, s.settling),
        (0, 1),
        "…but its mtime is not, and within the allowance the mtime counts"
    );
    e.close().unwrap();
}
