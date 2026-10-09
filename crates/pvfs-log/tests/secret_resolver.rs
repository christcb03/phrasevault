//! PVOS D226 — a `keychain:` secret resolves only through the process's
//! resolver. Its own binary: the resolver is set once per process.
#![cfg(feature = "ship")]

use pvfs_log::ship::{install_from_file, read_secret, set_secret_resolver};

#[test]
fn keychain_secrets_need_the_resolver_and_files_still_work() {
    let d = tempfile::tempdir().unwrap();
    let cfg = d.path().join("log-destinations.json");
    std::fs::write(d.path().join("splunk.token"), "file-token\n").unwrap();
    std::fs::write(
        &cfg,
        r#"{"v":1,"destinations":[
          {"name":"mac","type":"loki","url":"http://127.0.0.1:9","secret":"keychain:mac"},
          {"name":"filed","type":"loki","url":"http://127.0.0.1:9","secret":"splunk.token"}]}"#,
    )
    .unwrap();
    // No resolver yet: the keychain one is a problem naming it; the file one reads.
    let e = read_secret(&cfg, "keychain:mac").unwrap_err();
    assert!(e.contains("Keychain") && e.contains("companion"), "{e}");
    assert_eq!(read_secret(&cfg, "splunk.token").unwrap(), "file-token");
    let problems = install_from_file(&cfg, &d.path().join("spool"), "PVFS", "test").unwrap();
    assert!(problems.iter().any(|p| p.starts_with("mac: ") && p.contains("keychain:mac")), "{problems:?}");
    assert!(!problems.iter().any(|p| p.starts_with("filed:")), "{problems:?}");
    // With one: resolved (trimmed), and an unknown name is the resolver's error.
    set_secret_resolver(|name| if name == "mac" { Ok("kc-token\n".into()) } else { Err(format!("no item {name}")) });
    assert_eq!(read_secret(&cfg, "keychain:mac").unwrap(), "kc-token");
    assert!(read_secret(&cfg, "keychain:other").unwrap_err().contains("no item other"));
    let problems = install_from_file(&cfg, &d.path().join("spool"), "PVFS", "test").unwrap();
    assert!(!problems.iter().any(|p| p.contains("keychain")), "{problems:?}");
}
