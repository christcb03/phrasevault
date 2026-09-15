//! D150 revision — a manifest records its file's mtime (v3), and
//! `upgrade_sidecars` brings the existing ones up against the catalogue.
//!
//! Chris, 2026-09-14: *"if the hash is in the forest can we use that to compare
//! to the manifest hash to confirm it's what it should be? If so would that
//! allow us to update all the manifests to include the time stamp of the
//! matching file and use that instead of looking for older/newer time stamps
//! on the manifest? This would also be a fix for the 33."*

use pvfs_core::sync;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};
use std::path::Path;
use std::time::{Duration, SystemTime};

fn set_mtime(p: &Path, t: SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

/// The file's mtime in the catalogue's unit.
fn mtime_ms(p: &Path) -> u64 {
    std::fs::metadata(p)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn hash(b: &[u8]) -> String {
    blake3::hash(b).to_hex().to_string()
}

fn lines(file: &Path) -> Vec<String> {
    std::fs::read_to_string(sync::manifest_sidecar_path(file))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

/// A v2 manifest exactly as the fleet's pre-revision builds wrote them.
fn write_v2(file: &Path, whole: &str, size: u64, chunk_of: &[u8]) {
    std::fs::write(
        sync::manifest_sidecar_path(file),
        format!("pvfs-manifest 2\n{}\n{whole}\n{size}\n{}\n", sync::SWARM_CHUNK, hash(chunk_of)),
    )
    .unwrap();
}

#[test]
fn a_manifest_records_its_files_mtime() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("ep.mkv");
    std::fs::write(&f, b"episode one").unwrap();
    sync::manifest_for_caching(&f).unwrap();
    let l = lines(&f);
    assert_eq!(l[0], "pvfs-manifest 3");
    assert_eq!(l[3], "11", "the exact size");
    assert_eq!(l[4], mtime_ms(&f).to_string(), "the file's mtime, in the catalogue's unit");
    assert_eq!(sync::sidecar_whole_hash(&f, 11), Some(hash(b"episode one")));
}

/// The case the first D150 rule ("not older than the file") could not see: a
/// same-size replacement that brought an OLDER mtime with it — a copy that
/// kept its source's time.
#[test]
fn a_same_size_replacement_with_an_older_mtime_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("ep.mkv");
    std::fs::write(&f, b"AAAAAAAAAA").unwrap();
    set_mtime(&f, SystemTime::now() - Duration::from_secs(2 * 3600));
    sync::manifest_for_caching(&f).unwrap();

    std::fs::write(&f, b"BBBBBBBBBB").unwrap();
    set_mtime(&f, SystemTime::now() - Duration::from_secs(3 * 86_400));
    let side = sync::manifest_sidecar_path(&f);
    assert!(
        std::fs::metadata(&side).unwrap().modified().unwrap() > std::fs::metadata(&f).unwrap().modified().unwrap(),
        "the manifest file is NEWER than the file — the first rule would have trusted it"
    );
    assert!(
        sync::sidecar_whole_hash(&f, 10).is_none(),
        "same size, different bytes, a back-dated mtime: the recorded mtime is not the file's"
    );
}

/// The NAS ran 142 s slow and receive stamps a file with its SOURCE's mtime,
/// so a received file can be dated after the moment its manifest was written.
#[test]
fn a_clock_skewed_files_own_manifest_is_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("ep.mkv");
    std::fs::write(&f, b"received").unwrap();
    set_mtime(&f, SystemTime::now() + Duration::from_secs(16));
    let (whole, chunks) = sync::hash_with_manifest(&f).unwrap();
    sync::write_manifest_sidecar(&f, Some(&whole), &chunks).unwrap();
    assert_eq!(sync::sidecar_whole_hash(&f, 8), Some(whole));
}

#[test]
fn a_v2_manifest_keeps_the_first_rule_until_upgraded() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("ep.mkv");
    std::fs::write(&f, b"old library").unwrap();
    set_mtime(&f, SystemTime::now() - Duration::from_secs(3600));
    write_v2(&f, &hash(b"old library"), 11, b"old library");
    assert_eq!(
        sync::sidecar_whole_hash(&f, 11),
        Some(hash(b"old library")),
        "written after its file: trusted, as on the fleet today"
    );
    set_mtime(&sync::manifest_sidecar_path(&f), SystemTime::now() - Duration::from_secs(7200));
    assert!(sync::sidecar_whole_hash(&f, 11).is_none(), "older than its file: not trusted");
}

fn index(dir: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(dir.join("forest").join("index.db")).unwrap()
}

fn row_hash(dir: &Path, rel: &str) -> Option<String> {
    index(dir)
        .query_row("SELECT content_hash FROM region_entries WHERE rel_path = ?1", [rel], |r| r.get(0))
        .unwrap()
}

/// Make the row say what the pre-revision scan would have recorded.
fn set_row(dir: &Path, rel: &str, hash: &str, mtime: u64) {
    index(dir)
        .execute(
            "UPDATE region_entries SET content_hash = ?1, mtime_ms = ?2 WHERE rel_path = ?3",
            rusqlite::params![hash, mtime as i64, rel],
        )
        .unwrap();
}

/// The whole upgrade, on a catalogue region holding the three kinds of v2
/// manifest the NAS has: one the catalogue vouches for, one of the 33 whose
/// bytes changed, and one of the 33 whose bytes did not.
#[test]
fn the_upgrade_stamps_what_the_catalogue_vouches_for_and_rereads_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    let hour_ago = SystemTime::now() - Duration::from_secs(3600);
    for (name, bytes) in [("a.mkv", b"aaaaaaaa"), ("b.mkv", b"bbbbbbbb"), ("c.mkv", b"cccccccc")] {
        std::fs::write(lib.join(name), bytes).unwrap();
        set_mtime(&lib.join(name), hour_ago);
    }
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
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
    e.scan_routed(Some(&region), None, 0).unwrap();

    // a.mkv — a v2 manifest the catalogue vouches for. A SENTINEL in both, so
    // a stamped manifest still carrying it proves the file was never read.
    let a = lib.join("a.mkv");
    let sentinel = "5e0771e1".repeat(8);
    write_v2(&a, &sentinel, 8, b"aaaaaaaa");
    set_row(dir.path(), "a.mkv", &sentinel, mtime_ms(&a));

    // b.mkv — one of the 33 whose bytes DID change: rewritten in place at the
    // same size after its v2 manifest, and the pre-revision scan took the OLD
    // hash from that manifest into the row.
    let b = lib.join("b.mkv");
    let old_b = hash(b"bbbbbbbb");
    write_v2(&b, &old_b, 8, b"bbbbbbbb");
    set_mtime(&sync::manifest_sidecar_path(&b), hour_ago);
    std::fs::write(&b, b"BBBBBBBB").unwrap();
    set_row(dir.path(), "b.mkv", &old_b, mtime_ms(&b));

    // c.mkv — one of the 33 whose bytes did NOT change: its mtime moved after
    // its v2 manifest was written, nothing else.
    let c = lib.join("c.mkv");
    write_v2(&c, &hash(b"cccccccc"), 8, b"cccccccc");
    set_mtime(&sync::manifest_sidecar_path(&c), hour_ago - Duration::from_secs(60));
    set_row(dir.path(), "c.mkv", &hash(b"cccccccc"), mtime_ms(&c));

    // Look first: nothing is written.
    let plan = e.upgrade_sidecars(true).unwrap();
    assert_eq!((plan.files, plan.stamped, plan.reread), (3, 1, 2));
    assert_eq!(plan.reread_bytes, 16);
    assert_eq!(lines(&a)[0], "pvfs-manifest 2", "a look writes nothing");
    assert_eq!(row_hash(dir.path(), "b.mkv"), Some(old_b.clone()), "nor corrects anything");

    let done = e.upgrade_sidecars(false).unwrap();
    assert_eq!(done.stamped, 1);
    assert_eq!(done.verified, 1, "c.mkv: re-read, and the bytes are what the catalogue says");
    assert_eq!(done.corrected.len(), 1, "b.mkv: a stale hash caught");
    assert_eq!(done.corrected[0], ("b.mkv".to_string(), old_b, hash(b"BBBBBBBB")));

    let la = lines(&a);
    assert_eq!(la[0], "pvfs-manifest 3");
    assert_eq!(la[2], sentinel, "stamped, not re-read");
    assert_eq!(la[4], mtime_ms(&a).to_string());

    // The next scan takes b.mkv's TRUE hash from the fresh manifest.
    e.scan_routed(Some(&region), None, 0).unwrap();
    assert_eq!(row_hash(dir.path(), "b.mkv"), Some(hash(b"BBBBBBBB")));

    let again = e.upgrade_sidecars(true).unwrap();
    assert_eq!(
        (again.stamped, again.reread, again.already_current),
        (0, 0, 3),
        "a second upgrade has nothing left to do"
    );
}
