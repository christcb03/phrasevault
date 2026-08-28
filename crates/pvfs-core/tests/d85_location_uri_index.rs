//! D85 — locations are looked up by URI, so URI needs an index.
//!
//! `orphaned_local_locations` asks whether any OTHER live node claims the same
//! bytes — a match on `o.uri = l.uri`. Unindexed, that is a full scan of every
//! location per candidate row.
//!
//! It went unnoticed because the query matched nothing until the pin-qualified
//! fix landed, and the job was disabled. Enabling both in one deploy turned a
//! no-op into an O(n²) sweep: on the live holder it pinned a core and read the
//! catalog at 143 MB/s while producing nothing, starving the hash backfill that
//! shares the same database. Correctness had been checked; cost had not.
//!
//! Measured on a copy of the production catalog (57,410 locations):
//! **3.87 s before, 0.01 s after — 525x.**

use pvfs_core::Engine;

#[test]
fn locations_are_indexed_by_uri() {
    let dir = tempfile::tempdir().unwrap();
    let (e, _mn) = Engine::init(dir.path()).unwrap();
    let idx = e.debug_index_names().unwrap();
    assert!(
        idx.iter().any(|n| n == "idx_file_locations_uri"),
        "a location lookup by uri must be indexed, or reclaim rescans every \
         location per row: {idx:?}"
    );
    // The file_id lookup was already indexed; assert it too so a future schema
    // edit cannot quietly drop one while keeping the other.
    assert!(
        idx.iter().any(|n| n == "idx_file_locations_file"),
        "{idx:?}"
    );
    e.close().unwrap();
}
