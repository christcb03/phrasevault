//! D122 items 0–1 — the source earns its place, and the quarantine lookup
//! fails closed.
//!
//! On the production holder, 41,240 of 42,570 `stream failed` lines were
//! dials to the owner — a box that holds no bytes and was a candidate only
//! because it is the replica's SOURCE (doc 27 §0). The source is now a
//! candidate only when the catalogue says it could serve.

use pvfs_client::fetch::{attribute_mismatch, Fetcher};
use pvfs_core::replica::ReplicaSource;
use pvfs_core::{Engine, FilePayload, NodeSpec, TYPE_FILE};

/// D132 — a throwaway config dir for this binary, so no test here reads the
/// box's real instance registry (`XDG_CONFIG_HOME/pvfs/instances`). Set once
/// per process; every test in the file shares it, which is all the isolation
/// they need. The dir is deliberately leaked: the process is the lifetime.
fn isolate_config() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let dir = tempfile::tempdir().expect("config tempdir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::mem::forget(dir);
    });
}

const SOURCE_PIN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_PIN: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// A forest with one file whose locations are `locs`, then re-opened as a
/// REPLICA whose source is `SOURCE_PIN` — the holder's shape.
fn replica_with(dir: &std::path::Path, locs: &[&str]) -> (Engine, String) {
    let (mut e, _mn) = Engine::init(dir).unwrap();
    let root = e.identity.root_node_id.clone();
    let file = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "clip.mkv".into(),
                payload: FilePayload {
                    content_hash: "ab".repeat(32),
                    size_bytes: 3,
                    mime_type: "video/x-matroska".into(),
                    original_name: "clip.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    for l in locs {
        e.add_location(&file, l).unwrap();
    }
    e.close().unwrap();
    ReplicaSource {
        transport: "tcp".into(),
        target: "192.0.2.1:7421".into(),
        pin: SOURCE_PIN.into(),
        region: String::new(),
    }
    .save(dir)
    .unwrap();
    (Engine::open(dir).unwrap(), file)
}

fn source_candidates(e: &Engine, dir: &std::path::Path, file: &str) -> usize {
    Fetcher::new(dir)
        .candidates(e, file)
        .unwrap()
        .iter()
        .filter(|c| c.pin == SOURCE_PIN)
        .count()
}

/// The production case: every location is pin-qualified to ANOTHER box, so
/// the source holds nothing and is not asked.
#[test]
fn a_source_that_holds_nothing_is_not_a_candidate() {
    isolate_config();
    let dir = tempfile::tempdir().unwrap();
    let (e, file) = replica_with(
        dir.path(),
        &[&format!("pvfs-host://{OTHER_PIN}/Media/clip.mkv")],
    );
    assert_eq!(source_candidates(&e, dir.path(), &file), 0);
}

/// The lab shape: a bare `file://` location is host-implicit — the owner's
/// own disk — and the source is still asked.
#[test]
fn a_bare_file_location_keeps_the_source_as_a_candidate() {
    isolate_config();
    let dir = tempfile::tempdir().unwrap();
    let (e, file) = replica_with(dir.path(), &["file:///srv/media/clip.mkv"]);
    assert_eq!(source_candidates(&e, dir.path(), &file), 1);
}

/// A location pin-qualified to the source itself says the source holds it.
#[test]
fn a_location_at_the_source_pin_keeps_the_source_as_a_candidate() {
    isolate_config();
    let dir = tempfile::tempdir().unwrap();
    let (e, file) = replica_with(
        dir.path(),
        &[&format!("pvfs-host://{SOURCE_PIN}/Media/clip.mkv")],
    );
    assert_eq!(source_candidates(&e, dir.path(), &file), 1);
}

/// A quarantined location does not count as "the source holds it".
#[test]
fn a_quarantined_location_at_the_source_does_not_count() {
    isolate_config();
    let dir = tempfile::tempdir().unwrap();
    let uri = format!("pvfs-host://{SOURCE_PIN}/Media/clip.mkv");
    let (e, file) = replica_with(dir.path(), &[&uri]);
    e.quarantine_locations_at_pin(&file, SOURCE_PIN, "test: bytes did not match")
        .unwrap();
    assert_eq!(source_candidates(&e, dir.path(), &file), 0);
}

/// Fail closed: a DB error in the quarantine lookup is an error, not an
/// empty list that lets the fetch proceed onto bytes it cannot vouch for.
#[test]
fn a_broken_quarantine_lookup_is_an_error_not_an_empty_list() {
    isolate_config();
    let dir = tempfile::tempdir().unwrap();
    let (e, file) = replica_with(dir.path(), &["file:///srv/media/clip.mkv"]);
    // Pull the table out from under the open engine.
    let c = rusqlite::Connection::open(dir.path().join("index.db")).unwrap();
    c.execute_batch("ALTER TABLE location_quarantine RENAME TO location_quarantine_gone")
        .unwrap();
    let r = Fetcher::new(dir.path()).candidates(&e, &file);
    assert!(r.is_err(), "must not proceed: {r:?}");
}

/// Item 0 — attribution by who served: exactly one contributor names the
/// stale holder; none or several do not.
#[test]
fn a_mismatch_is_attributed_only_when_one_holder_served() {
    isolate_config();
    let one = vec![("tcp:a:1".to_string(), 7u64), ("tcp:b:2".to_string(), 0)];
    assert_eq!(attribute_mismatch(&one), Some("tcp:a:1"));
    let two = vec![("tcp:a:1".to_string(), 3u64), ("tcp:b:2".to_string(), 4)];
    assert_eq!(attribute_mismatch(&two), None);
    let none: Vec<(String, u64)> = vec![("tcp:a:1".to_string(), 0)];
    assert_eq!(attribute_mismatch(&none), None);
}
