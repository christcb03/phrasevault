//! D222 decision 4: the names PVFS logs are a contract. Every `pv_*!` event
//! in the daemon-side crates is listed in docs/32-log-events.md (with the
//! category it is logged under), every listed name is still logged, and no
//! `eprintln!` is left to go around the logger.

use std::path::Path;

#[test]
fn pvfs_event_names_match_the_list() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let problems = pvfs_log::registry::check_repo(
        &root,
        "docs/32-log-events.md",
        &["crates/pvfsd", "crates/pvfs-core", "crates/pvfs-client", "crates/pvfs-fuse", "crates/pvfs-companion"],
        "pvfs.",
    );
    assert!(problems.is_empty(), "{} problem(s):\n{}", problems.len(), problems.join("\n"));
}
