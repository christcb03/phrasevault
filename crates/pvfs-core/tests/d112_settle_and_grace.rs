//! D112 — the two faults behind production's 1,901 `missing` entries.
//!
//! **The settle window trusted mtime.** It asked "has this stopped moving?"
//! with `mtime + 15s > now`, on the reasoning that a growing file's mtime keeps
//! advancing. True of a local copier like Sonarr; false of anything that
//! back-dates the destination. cloudplow rclones feederbox → NAS preserving the
//! SOURCE mtime, so a file that landed thirty seconds ago carries an mtime from
//! two days back, clears the window on its first sighting, and is catalogued
//! mid-copy at a partial size. Measured on the holder 2026-09-08: arrivals with
//! mtime 41.8h and 56.5h BEHIND their ctime.
//!
//! That mis-sized node then failed `match_by_identity` against the node the
//! ingest box had already made for the same file, and a DUPLICATE was minted —
//! two nodes, same label, same tree path, different authors, one holding the
//! location and one holding nothing. The empty one is what `missing` reported.
//!
//! **And D105 unlinked on "no live location".** On this fleet that is a
//! transient state every time the mover runs, so the fix is to treat it as an
//! observation and act only if it is still true a grace period later.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn setup(dir: &std::path::Path) -> (Engine, String, std::path::PathBuf) {
    let lib = dir.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    let (mut e, _mn) = Engine::init(&dir.join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();
    let folder = e
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
    e.bind_folder(
        &folder,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    (e, folder, lib)
}

fn file_names(e: &Engine, folder: &str) -> Vec<String> {
    e.children(&folder.to_string())
        .unwrap()
        .into_iter()
        .filter(|c| c.node.node_type == TYPE_FILE)
        .map(|c| c.label)
        .collect()
}

/// Back-date a file's mtime the way rclone does. ctime is untouched by this —
/// the kernel sets it on the utimes call itself, which is exactly the property
/// the fix leans on.
fn backdate_mtime(path: &std::path::Path, days: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
    let secs = when
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let out = std::process::Command::new("touch")
        .arg("-d")
        .arg(format!("@{secs}"))
        .arg(path)
        .output()
        .expect("touch");
    assert!(out.status.success(), "touch failed: {out:?}");
}

/// The regression itself: a file whose mtime is two days old but which landed
/// just now must be treated as STILL SETTLING, not catalogued at its current
/// (possibly partial) size.
#[test]
fn a_backdated_mtime_does_not_defeat_the_settle_window() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, folder, lib) = setup(dir.path());

    let f = lib.join("Lanterns - s01e04.mkv");
    std::fs::write(&f, vec![7u8; 4096]).unwrap();
    backdate_mtime(&f, 2);

    // Prove the premise rather than trusting `touch`: mtime really is behind.
    let md = std::fs::metadata(&f).unwrap();
    let mtime = md
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(now - mtime > 86_400, "the test must back-date the mtime");

    let reports = e
        .scan_routed(Some(&folder), None, pvfs_core::WATCH_SETTLE_MS)
        .unwrap();
    let s = &reports[0].stats;
    assert_eq!(
        s.added, 0,
        "a file that landed seconds ago must not be catalogued because rclone \
         gave it an old mtime — that is how a partial copy gets its size recorded"
    );
    assert_eq!(s.settling, 1, "it must be DEFERRED, not skipped or dropped");
    assert!(file_names(&e, &folder).is_empty());

    // …and once it has genuinely stopped moving, it lands normally.
    let reports = e.scan_routed(Some(&folder), None, 0).unwrap();
    assert_eq!(reports[0].stats.added, 1);
    assert_eq!(file_names(&e, &folder), vec!["Lanterns - s01e04.mkv"]);
    e.close().unwrap();
}

/// D105's unlink now waits. Held-nowhere is an observation, and on a fleet
/// whose mover runs outside the catalog it is a routine transient one.
#[test]
fn a_file_held_nowhere_is_not_unlinked_until_the_grace_expires() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, folder, lib) = setup(dir.path());
    std::fs::write(lib.join("moved.mkv"), vec![3u8; 2048]).unwrap();
    e.scan_routed(Some(&folder), None, 0).unwrap();
    assert_eq!(file_names(&e, &folder), vec!["moved.mkv"]);

    // cloudplow takes it away without telling PVFS.
    std::fs::remove_file(lib.join("moved.mkv")).unwrap();
    let s = &e.scan_routed(Some(&folder), None, 0).unwrap()[0].stats;
    assert_eq!(s.removed, 1, "the location is still retired immediately");
    assert_eq!(
        s.unlinked, 0,
        "but the node MUST NOT leave the tree yet — the holder may simply not \
         have recorded its copy of this file yet"
    );
    assert_eq!(s.pending_unlink, 1, "and the wait must be reported");
    assert_eq!(
        file_names(&e, &folder),
        vec!["moved.mkv"],
        "still browsable while the grace runs"
    );

    // A second pass inside the grace changes nothing — the clock does not
    // restart, and it does not fire early either.
    let s = &e.scan_routed(Some(&folder), None, 0).unwrap()[0].stats;
    assert_eq!(s.unlinked, 0);

    let data = e.data_dir().to_path_buf();
    e.close().unwrap();

    // Age the note past the grace, exactly as a day of real time would.
    let conn = rusqlite::Connection::open(data.join("index.db")).unwrap();
    let rows = conn
        .execute(
            "UPDATE scan_unheld SET since_ms = since_ms - ?1",
            rusqlite::params![(pvfs_core::UNLINK_GRACE_MS + 60_000) as i64],
        )
        .unwrap();
    assert_eq!(rows, 1, "exactly one file should be waiting");
    drop(conn);

    let mut e = Engine::open(&data).unwrap();
    let s = &e.scan_routed(Some(&folder), None, 0).unwrap()[0].stats;
    assert_eq!(s.unlinked, 1, "now it goes");
    assert!(
        file_names(&e, &folder).is_empty(),
        "and it is out of the tree"
    );
    e.close().unwrap();
}

/// The cancel path, which is the one that protects real files: a location
/// appearing anywhere stops the clock, so the file never leaves the tree.
#[test]
fn a_location_appearing_cancels_the_pending_unlink() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, folder, lib) = setup(dir.path());
    std::fs::write(lib.join("moved.mkv"), vec![4u8; 2048]).unwrap();
    e.scan_routed(Some(&folder), None, 0).unwrap();
    let id = e
        .children(&folder)
        .unwrap()
        .into_iter()
        .find(|c| c.node.node_type == TYPE_FILE)
        .unwrap()
        .node
        .id;

    std::fs::remove_file(lib.join("moved.mkv")).unwrap();
    assert_eq!(e.scan_routed(Some(&folder), None, 0).unwrap()[0].stats.pending_unlink, 1);

    // The holder finally records the copy it has had all along.
    e.add_location(&id, "pvfs-host://somebox/share/Media/moved.mkv")
        .unwrap();

    // Age what WOULD have been the deadline. Nothing is waiting any more, so
    // there is nothing to age — and the file stays.
    let data = e.data_dir().to_path_buf();
    e.close().unwrap();
    let conn = rusqlite::Connection::open(data.join("index.db")).unwrap();
    let waiting: i64 = conn
        .query_row("SELECT COUNT(*) FROM scan_unheld", [], |r| r.get(0))
        .unwrap();
    assert_eq!(waiting, 0, "the note must be cleared by the arriving location");
    drop(conn);

    let mut e = Engine::open(&data).unwrap();
    let s = &e.scan_routed(Some(&folder), None, 0).unwrap()[0].stats;
    assert_eq!(s.unlinked, 0, "a file somebody holds never leaves the tree");
    assert_eq!(file_names(&e, &folder), vec!["moved.mkv"]);
    e.close().unwrap();
}
