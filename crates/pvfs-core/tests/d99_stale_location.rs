//! D99 — a remote location that no longer holds what the catalog names.
//!
//! The production shape: the *arr stack overwrote a media file in place with a
//! better encode. PVFS still bound the OLD content id to that path, so the
//! holder fetched, received bytes hashing to something else, correctly refused
//! the commit — and repeated, forever. Five files produced 1,814 log lines.
//!
//! `read_verified` already quarantines a LOCAL read whose bytes miss their
//! hash. The remote path only printed. These tests cover the parity fix and the
//! memory that keeps a doomed fetch from being re-attempted after a restart.

use pvfs_core::{Engine, FilePayload, NodeSpec, TYPE_FILE};

fn file_node(e: &mut Engine, parent: &str, label: &str, size: u64) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec {
            node_type: TYPE_FILE.into(),
            label: label.into(),
            payload: FilePayload {
                content_hash: String::new(),
                size_bytes: size,
                mime_type: "video/x-matroska".into(),
                original_name: label.into(),
            }
            .encode(),
            is_temp: false,
            creation_nonce: None,
        },
    )
    .unwrap()
}

fn quarantine_reason(e: &mut Engine, id: &str, uri: &str) -> Option<String> {
    e.stat_node(&id.to_string())
        .unwrap()
        .locations
        .into_iter()
        .find(|l| l.uri == uri)
        .and_then(|l| l.quarantined)
}

/// The fix itself: the stale holder's location is quarantined, and ONLY that
/// one. A file served by two holders where one has drifted must keep the good
/// holder usable — quarantining by node rather than by location would strand
/// bytes that are perfectly fine.
#[test]
fn only_the_drifted_holders_location_is_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();

    let id = file_node(&mut e, &root, "Piccolo's Return.mkv", 3_371_964_304);
    let stale_pin = "aa".repeat(32);
    let good_pin = "bb".repeat(32);
    let stale = format!("pvfs-host://{stale_pin}/mnt/local/Media/piccolo.mkv");
    let good = format!("pvfs-host://{good_pin}/share/Data/Media/piccolo.mkv");
    e.add_location(&id, &stale).unwrap();
    e.add_location(&id, &good).unwrap();

    let hit = e
        .quarantine_locations_at_pin(&id, &stale_pin, "id mismatch on fetch")
        .unwrap();

    assert_eq!(hit, vec![stale.clone()], "only the failing pin is recorded");
    assert!(
        quarantine_reason(&mut e, &id, &stale).is_some(),
        "the drifted location must be quarantined"
    );
    assert!(
        quarantine_reason(&mut e, &id, &good).is_none(),
        "the other holder still has good bytes and must stay usable"
    );
    e.close().unwrap();
}

/// The reason is carried through, because an operator reading `loc ls` has to
/// be able to tell this apart from a local read failure.
#[test]
fn the_quarantine_says_why() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();

    let id = file_node(&mut e, &root, "ep.mkv", 512);
    let pin = "cc".repeat(32);
    let uri = format!("pvfs-host://{pin}/mnt/local/ep.mkv");
    e.add_location(&id, &uri).unwrap();

    e.quarantine_locations_at_pin(&id, &pin, "id mismatch on fetch: expected X, recomputed Y")
        .unwrap();

    let reason = quarantine_reason(&mut e, &id, &uri).unwrap();
    assert!(
        reason.contains("id mismatch on fetch"),
        "the reason must name the failure: {reason}"
    );
    e.close().unwrap();
}

/// A pin nobody serves changes nothing — the guard against a typo'd or stale
/// pin quietly quarantining a healthy library.
#[test]
fn an_unknown_pin_quarantines_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();

    let id = file_node(&mut e, &root, "ep.mkv", 512);
    let uri = format!("pvfs-host://{}/mnt/local/ep.mkv", "dd".repeat(32));
    e.add_location(&id, &uri).unwrap();

    let hit = e
        .quarantine_locations_at_pin(&id, &"ee".repeat(32), "id mismatch on fetch")
        .unwrap();

    assert!(hit.is_empty(), "no location at that pin");
    assert!(quarantine_reason(&mut e, &id, &uri).is_none());
    e.close().unwrap();
}

/// The mover's memory survives a restart. Held only in daemon memory, this set
/// died with every restart and the next pass spent eight hours re-asking ~24k
/// holders a question already answered "nobody".
#[test]
fn the_unfetchable_set_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let forest = dir.path().join("forest");
    let (e, _mn) = Engine::init(&forest).unwrap();
    assert!(e.unfetchable_load().unwrap().is_empty(), "starts empty");

    e.unfetchable_save(&["node-a".to_string(), "node-b".to_string()])
        .unwrap();
    e.close().unwrap();

    // the restart
    let e = Engine::open(&forest).unwrap();
    let mut got = e.unfetchable_load().unwrap();
    got.sort();
    assert_eq!(got, vec!["node-a".to_string(), "node-b".to_string()]);

    // saving a known id again is not an error and does not duplicate it
    e.unfetchable_save(&["node-a".to_string()]).unwrap();
    assert_eq!(e.unfetchable_load().unwrap().len(), 2);

    // the periodic amnesia must clear the DURABLE copy too, or the next
    // restart resurrects exactly what was just forgiven.
    e.unfetchable_clear().unwrap();
    assert!(e.unfetchable_load().unwrap().is_empty());
    e.close().unwrap();
}

/// The fetcher's candidate list is filtered on exactly this, so what it
/// returns has to be exact: quarantining one location of a node must not
/// report the node's OTHER locations as banned.
#[test]
fn quarantined_uris_names_only_what_was_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();

    let id = file_node(&mut e, &root, "ep.mkv", 512);
    let bad_pin = "aa".repeat(32);
    let bad = format!("pvfs-host://{bad_pin}/mnt/local/ep.mkv");
    let good = format!("pvfs-host://{}/share/Data/ep.mkv", "bb".repeat(32));
    e.add_location(&id, &bad).unwrap();
    e.add_location(&id, &good).unwrap();

    assert!(
        e.quarantined_uris(&id).unwrap().is_empty(),
        "nothing is banned before anything fails"
    );

    e.quarantine_locations_at_pin(&id, &bad_pin, "id mismatch on fetch")
        .unwrap();

    assert_eq!(e.quarantined_uris(&id).unwrap(), vec![bad]);

    // and `locations()` still returns BOTH — evict, reclaim and loc_verify all
    // depend on seeing a quarantined location, and verify is how the
    // quarantine gets lifted. Only the candidate list filters.
    assert_eq!(
        e.locations(&id).unwrap().len(),
        2,
        "quarantine must not hide a location from the rest of the system"
    );
    e.close().unwrap();
}
