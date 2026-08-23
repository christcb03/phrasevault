//! D82 — a mount must serve bytes it does not hold.
//!
//! The presentation layer replaces rclone as what Plex and the arrs read, so a
//! box with NO local copies has to serve the whole library from the catalog.
//! Staging it found the mount returning EIO for exactly those files: the P10.1
//! ingest-proxy path claims any node that is "unhashed with no local bytes",
//! dials the LOCAL daemon — which has nothing — and never falls through to the
//! resolve that would have fetched it.
//!
//! `pvfs cat` on the same node worked. Under a mount serving a media library,
//! that difference is the whole library returning I/O errors.

use pvfs_core::storage::{held_on_another_host, host_uri};

const MINE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const THEIRS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn h(pin: &str, p: &str) -> String {
    host_uri(pin, std::path::Path::new(p)).unwrap()
}

/// The case that was broken: the bytes are on another holder.
#[test]
fn a_file_held_by_another_box_is_not_an_in_flight_ingest() {
    let locs = vec![h(THEIRS, "/share/Data/Media/TV/Show/ep.mkv")];
    assert!(
        held_on_another_host(&locs, Some(MINE)),
        "another holder's copy must not be mistaken for something being \
         ingested HERE — that mistake returns EIO for every file the NAS holds"
    );
}

/// Our own pin-qualified copy is ours, and must not trip it.
#[test]
fn our_own_pin_qualified_copy_is_not_elsewhere() {
    let locs = vec![h(MINE, "/srv/media/TV/Show/ep.mkv")];
    assert!(!held_on_another_host(&locs, Some(MINE)));
}

/// A genuine in-flight ingest has only host-implicit local paths — the proxy
/// path must still be available to it.
#[test]
fn a_local_only_file_still_reaches_the_ingest_proxy() {
    let locs = vec!["file:///mnt/local/Media/TV/Show/ep.mkv".to_string()];
    assert!(
        !held_on_another_host(&locs, Some(MINE)),
        "a file with only local paths is exactly the in-flight ingest case"
    );
}

/// Mixed: it is here AND there. Still resolvable locally, so not "elsewhere"
/// for the purposes of the proxy decision — but the helper reports the fact,
/// and the caller only consults it when there are no local bytes.
#[test]
fn a_file_in_both_places_reports_the_remote_copy() {
    let locs = vec![
        "file:///mnt/local/Media/TV/Show/ep.mkv".to_string(),
        h(THEIRS, "/share/Data/Media/TV/Show/ep.mkv"),
    ];
    assert!(held_on_another_host(&locs, Some(MINE)));
}

/// A box that has never served a listener has no pin of its own — so ANY
/// pin-qualified location belongs to somebody else, because it could not have
/// written one.
#[test]
fn without_a_pin_of_our_own_every_qualified_location_is_someone_elses() {
    let locs = vec![h(THEIRS, "/share/Data/Media/TV/Show/ep.mkv")];
    assert!(held_on_another_host(&locs, None));
    let local = vec!["file:///mnt/local/x.mkv".to_string()];
    assert!(!held_on_another_host(&local, None));
}

/// Blobs are not host-qualified and say nothing about which box holds them.
#[test]
fn sync_store_blobs_do_not_count_as_elsewhere() {
    let locs = vec!["pvfs-sync:///abc123".to_string()];
    assert!(!held_on_another_host(&locs, Some(MINE)));
}
