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

/// PVOS D229: every warning and error PVFS logs says what kind of failure it
/// is — through its `error`/`reason` text or an `error_kind` it states. The
/// logging library's own calls count too; its unit tests' made-up events do
/// not.
#[test]
fn every_pvfs_failure_record_has_an_error_kind() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dirs: Vec<std::path::PathBuf> =
        ["crates/pvfsd", "crates/pvfs-core", "crates/pvfs-client", "crates/pvfs-fuse", "crates/pvfs-companion", "crates/pvfs-log"]
            .iter()
            .map(|c| root.join(c).join("src"))
            .collect();
    let sources: Vec<_> = pvfs_log::registry::sources(&dirs)
        .into_iter()
        .filter(|(f, _)| !f.file_name().is_some_and(|n| n == "tests.rs" || n == "testing.rs"))
        .collect();
    let uses = pvfs_log::registry::uses(&sources);
    assert!(uses.iter().filter(|u| u.severity <= pvfs_log::Severity::Warning).count() > 100, "the scan found the calls");
    let problems = pvfs_log::registry::check_error_kinds(&uses);
    assert!(problems.is_empty(), "{} problem(s):\n{}", problems.len(), problems.join("\n"));
}
