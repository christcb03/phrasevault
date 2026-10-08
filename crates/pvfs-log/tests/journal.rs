//! D222: a record really reaches journald with its fields (Linux; the
//! pipeline's build host has systemd and the pipeline user reads the
//! journal through `adm`). No skip: if the journal cannot be read back the
//! test fails.
#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::{Duration, Instant};

use pvfs_log::{Category, Class, Field, Outcome, Record, Severity, Value};

#[test]
fn a_record_reaches_the_journal_with_its_fields() {
    let ident = format!("pvfs-log-test-{}", std::process::id());
    let mut r = Record::now(Severity::Warning, "pvfs.job.failed", "pvfsd: watch pass failed: test; retrying".into());
    r.category = Category::Security;
    r.outcome = Some(Outcome::Failure);
    r.fields = vec![
        Field { name: "job".into(), class: Class::Meta, value: Value::Str("watch".into()) },
        Field { name: "error".into(), class: Class::Content, value: Value::Str("line one\nline two".into()) },
        Field { name: "passes".into(), class: Class::Meta, value: Value::UInt(3) },
    ];
    pvfs_log::__send_record(&r, &ident).expect("journald accepts the datagram");

    let deadline = Instant::now() + Duration::from_secs(10);
    let entry = loop {
        let out = Command::new("journalctl")
            .args(["-t", &ident, "-o", "json", "--no-pager", "-n", "1"])
            .output()
            .expect("journalctl runs");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        if let Some(line) = text.lines().find(|l| l.starts_with('{')) {
            break serde_json::from_str::<serde_json::Value>(line).expect("journalctl json");
        }
        assert!(Instant::now() < deadline, "no journal entry for {ident}: {}", String::from_utf8_lossy(&out.stderr));
        std::thread::sleep(Duration::from_millis(200));
    };
    let s = |k: &str| entry.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    assert_eq!(s("MESSAGE"), "pvfsd: watch pass failed: test; retrying");
    assert_eq!(s("PRIORITY"), "4");
    assert_eq!(s("PV_SCHEMA"), "1");
    assert_eq!(s("PV_EVENT"), "pvfs.job.failed");
    assert_eq!(s("PV_CATEGORY"), "security");
    assert_eq!(s("PV_OUTCOME"), "failure");
    assert_eq!(s("PV_COMPONENT"), "pvfsd");
    assert_eq!(s("PV_JOB"), "watch");
    assert_eq!(s("PV_PASSES"), "3");
    assert_eq!(s("PV_ID"), r.id);
    // A value with a newline went in length-prefixed; journalctl prints a
    // value with control characters as an array of bytes.
    let err = entry.get("PV_ERROR").expect("PV_ERROR present");
    let bytes: Vec<u8> = match err {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Array(a) => a.iter().filter_map(|b| b.as_u64()).map(|b| b as u8).collect(),
        other => panic!("PV_ERROR as {other}"),
    };
    assert_eq!(bytes, b"line one\nline two");
}
