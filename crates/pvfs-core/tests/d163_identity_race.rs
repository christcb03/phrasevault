//! D163 — one box, one client identity, however many ask for it at once.
//!
//! `client_identity_mnemonic` used to make the phrase with a check, a
//! `File::create` and a write. Two callers that found no file each wrote a
//! phrase; the second `create` truncated the first's, and a write could land
//! on top of the other's (a 25-word file, GitHub CI 2026-09-16). The loser
//! kept a phrase the file no longer held, so its next dial was a stranger's.
//! Its own test binary: `XDG_CONFIG_HOME` is process-wide.
use std::sync::{Arc, Barrier};

use pvfs_core::identity;

#[test]
fn many_first_callers_at_once_hold_the_one_phrase_the_file_holds() {
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", tmp.path());
    let path = tmp.path().join("pvfs").join("identity.phrase");
    assert!(!path.exists());

    // Everyone starts at the same instant, the way two tests of one binary
    // did when a `OnceLock` released them together.
    let n = 16;
    let start = Arc::new(Barrier::new(n));
    let callers: Vec<_> = (0..n)
        .map(|_| {
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                identity::client_identity_mnemonic().map(|m| m.to_string())
            })
        })
        .collect();
    let held: Vec<String> = callers
        .into_iter()
        .map(|c| c.join().unwrap().expect("every caller gets a phrase"))
        .collect();

    let on_disk = std::fs::read_to_string(&path).unwrap();
    let phrase = on_disk.trim();
    assert_eq!(
        phrase.split_whitespace().count(),
        24,
        "the file holds one whole phrase: {on_disk:?}"
    );
    identity::parse_mnemonic(phrase).expect("and it parses");
    for h in &held {
        assert_eq!(h, phrase, "every caller holds the phrase the file holds");
    }

    // Nothing private left beside it, and the file itself is private.
    let beside: Vec<String> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "identity.phrase")
        .collect();
    assert!(beside.is_empty(), "no leftovers: {beside:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
    }

    // A later caller reads it back rather than making another.
    assert_eq!(identity::client_identity_mnemonic().unwrap().to_string(), phrase);

    // A phrase already on disk is what everyone gets — never replaced.
    let theirs = identity::generate_mnemonic().unwrap().to_string();
    std::fs::write(&path, format!("{theirs}\n")).unwrap();
    let again: Vec<String> = (0..4)
        .map(|_| std::thread::spawn(|| identity::client_identity_mnemonic().unwrap().to_string()))
        .collect::<Vec<_>>()
        .into_iter()
        .map(|c| c.join().unwrap())
        .collect();
    assert!(again.iter().all(|a| *a == theirs), "{again:?} vs {theirs}");
    assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), theirs);
}
