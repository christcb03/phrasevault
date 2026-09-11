//! D122 item 7 — one memory, one constructor. A fetcher built with
//! `with_memory` knows what earlier passes found nowhere; `persist_learned`
//! writes back only what THIS fetcher found out.

use pvfs_client::fetch::Fetcher;
use pvfs_core::Engine;

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

#[test]
fn a_fetcher_with_memory_knows_what_was_saved_and_saves_only_what_it_learned() {
    isolate_config();
    let dir = tempfile::tempdir().unwrap();
    let (e, _mn) = Engine::init(dir.path()).unwrap();
    e.unfetchable_save(&["old-1".to_string(), "old-2".to_string()]).unwrap();

    let mut f = Fetcher::with_memory(&e, dir.path());
    assert!(f.unfetchable().contains("old-1") && f.unfetchable().contains("old-2"), "seeded from the durable set");
    assert!(f.persist_learned(&e).is_empty(), "nothing learned yet, nothing written");

    // What a pass would note, plus what a job seeded from its own memory.
    f.seed_unfetchable(["job-mem".to_string()]);
    f.note_unfetchable("new-1");
    let mut fresh = f.persist_learned(&e);
    fresh.sort();
    assert_eq!(fresh, vec!["new-1".to_string()], "seeded ids are not re-saved; learned ones are");
    let mut saved = e.unfetchable_load().unwrap();
    saved.sort();
    assert_eq!(saved, vec!["new-1".to_string(), "old-1".to_string(), "old-2".to_string()]);
    assert!(f.persist_learned(&e).is_empty(), "and only once");
}

/// A bare fetcher still works — memory is opt-in for callers that have no
/// engine at hand — and starts empty.
#[test]
fn a_bare_fetcher_starts_with_no_memory() {
    isolate_config();
    let dir = tempfile::tempdir().unwrap();
    let (e, _mn) = Engine::init(dir.path()).unwrap();
    e.unfetchable_save(&["old-1".to_string()]).unwrap();
    assert!(Fetcher::new(dir.path()).unfetchable().is_empty());
}
