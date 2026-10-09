//! PVOS D229 — the log level, changed while a process runs, through the
//! data dir's `log-level.json`. One test: the level is process-wide.

use pvfs_log::level::{self, Watcher};
use pvfs_log::{Severity, Value};

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

fn field(r: &pvfs_log::Record, name: &str) -> String {
    r.fields.iter().find(|f| f.name == name).map(|f| f.value.to_string()).unwrap_or_default()
}

#[test]
fn a_live_level_applies_reverts_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(pvfs_log::current_level(), Severity::Info, "premise: the configured level");
    assert!(!pvfs_log::enabled(Severity::Debug));
    let mut w = Watcher::new();

    // No file: nothing changes, nothing is said.
    let recs = pvfs_log::capture(|| assert!(!w.apply(dir.path(), now())));
    assert!(recs.is_empty());

    // Debug for 2 minutes: applied, said once, and debug records are made.
    let f = level::write(dir.path(), Some(Severity::Debug), 2, "key:4f1c", now()).unwrap().unwrap();
    assert_eq!(f.level, "debug");
    assert!(f.until_ms > now() + 60_000 && f.until_ms <= now() + 120_000);
    let recs = pvfs_log::capture(|| assert!(w.apply(dir.path(), now())));
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = &recs[0];
    assert_eq!(r.event, "pvfs.log.level_changed");
    assert_eq!(r.category, pvfs_log::Category::Audit);
    assert_eq!(field(r, "level"), "debug");
    assert_eq!(field(r, "previous"), "info");
    assert_eq!(field(r, "reason"), "set");
    assert_eq!(field(r, "by"), "key:4f1c");
    assert!(matches!(r.fields.iter().find(|f| f.name == "until_ms").map(|f| &f.value), Some(Value::UInt(u)) if *u == f.until_ms));
    assert_eq!(pvfs_log::current_level(), Severity::Debug);
    assert!(pvfs_log::enabled(Severity::Debug));
    assert_eq!(level::override_until(), Some((Severity::Debug, f.until_ms)));
    // The same file again: nothing new.
    let recs = pvfs_log::capture(|| assert!(!w.apply(dir.path(), now())));
    assert!(recs.is_empty());

    // Its time runs out (as the watcher sees it): back, said once, "expired".
    let later = f.until_ms + 1;
    let recs = pvfs_log::capture(|| assert!(w.apply(dir.path(), later)));
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(field(&recs[0], "reason"), "expired");
    assert_eq!(field(&recs[0], "level"), "info");
    assert_eq!(pvfs_log::current_level(), Severity::Info);
    assert!(!pvfs_log::enabled(Severity::Debug));

    // A new level, then `default` (the file goes): "cleared".
    level::write(dir.path(), Some(Severity::Notice), 5, "key:4f1c", now()).unwrap();
    assert!(w.apply(dir.path(), now()));
    assert_eq!(pvfs_log::current_level(), Severity::Notice);
    assert_eq!(level::write(dir.path(), None, 0, "key:4f1c", now()).unwrap(), None);
    assert!(!level::path(dir.path()).exists());
    let recs = pvfs_log::capture(|| assert!(w.apply(dir.path(), now())));
    assert_eq!(field(&recs[0], "reason"), "cleared");
    assert_eq!(pvfs_log::current_level(), Severity::Info);

    // Minutes are clamped to a day.
    let f = level::write(dir.path(), Some(Severity::Debug), 100_000, "k", now()).unwrap().unwrap();
    assert!(f.until_ms <= now() + u64::from(level::MAX_MINUTES) * 60_000);
    level::write(dir.path(), None, 0, "k", now()).unwrap();
    w.apply(dir.path(), now());

    // An unreadable file changes nothing and is named once.
    std::fs::write(level::path(dir.path()), b"{not json").unwrap();
    let recs = pvfs_log::capture(|| {
        assert!(!w.apply(dir.path(), now()));
        assert!(!w.apply(dir.path(), now()));
    });
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0].event, "pvfs.log.level_file_unreadable");
    assert_eq!(field(&recs[0], "error_kind"), "config:level_file");
    std::fs::write(level::path(dir.path()), br#"{"level":"emergency","until_ms":99999999999999}"#).unwrap();
    let recs = pvfs_log::capture(|| assert!(!w.apply(dir.path(), now())));
    assert_eq!(recs.len(), 1, "a level a person may not set is a problem: {recs:?}");
    assert_eq!(pvfs_log::current_level(), Severity::Info);

    assert_eq!(level::parse_settable("warn"), Some(Severity::Warning));
    assert_eq!(level::parse_settable("crit"), None);
}
