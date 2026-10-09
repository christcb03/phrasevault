//! PVOS D225 — a panic is a `pvfs.thread.panicked` record. Its own test binary: the
//! hook is process-wide.

use pvfs_log::testing::GlobalCapture;
use pvfs_log::{render, Outcome, Privacy, Severity, Value};

fn field<'a>(r: &'a pvfs_log::Record, name: &str) -> Option<&'a Value> {
    r.fields.iter().find(|f| f.name == name).map(|f| &f.value)
}

#[test]
fn a_panic_becomes_a_critical_record_and_the_hook_does_not_recurse() {
    let logs = GlobalCapture::start();
    pvfs_log::install_panic_hook();
    pvfs_log::install_panic_hook(); // twice: still one hook
    let t = std::thread::Builder::new()
        .name("worker-7".into())
        .spawn(|| panic!("could not open /srv/media/Films/Secret (2026)/x.mkv"))
        .unwrap();
    assert!(t.join().is_err(), "the thread panicked");
    let got = logs.events("pvfs.thread.panicked");
    assert_eq!(got.len(), 1, "{got:?}");
    let r = &got[0];
    assert_eq!(r.severity, Severity::Critical);
    assert_eq!(r.outcome, Some(Outcome::Failure));
    assert_eq!(field(r, "thread"), Some(&Value::Str("worker-7".into())));
    match field(r, "at") {
        Some(Value::Str(at)) => assert!(at.contains("panic.rs:"), "{at}"),
        other => panic!("at: {other:?}"),
    }
    assert!(r.msg.contains("PANIC in thread 'worker-7'") && r.msg.contains("Secret (2026)"), "{}", r.msg);
    // The message is content: a destination at `minimal` never sees the path.
    let v = render(r, Privacy::Minimal, Some(&[5u8; 32]));
    assert!(!v.line().contains("Secret"), "{}", v.line());

    // A second panic is a second record (the guard was reset).
    let t = std::thread::Builder::new().name("worker-8".into()).spawn(|| panic!("again")).unwrap();
    assert!(t.join().is_err());
    let got = logs.events("pvfs.thread.panicked");
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(field(&got[1], "thread"), Some(&Value::Str("worker-8".into())));
}
