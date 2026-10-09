//! PVOS D229 — every record at warning or above says what kind of failure
//! it is (`error_kind`), and the PVFS scan holds every call to it.

use std::path::PathBuf;

use pvfs_log::kind::{classify, from_event, from_text, valid};
use pvfs_log::{content, pv_error, pv_info, pv_warn, Value};

fn kind_of(r: &pvfs_log::Record) -> Option<String> {
    r.fields.iter().find(|f| f.name == "error_kind").map(|f| f.value.to_string())
}

#[test]
fn the_texts_rust_tls_sqlite_and_pvfs_print_are_classified() {
    let io = |k: std::io::ErrorKind, raw: i32| {
        // As the OS words it, and as PVFS wraps it.
        let e = std::io::Error::from_raw_os_error(raw);
        assert_eq!(e.kind(), k, "premise: errno {raw}");
        e.to_string()
    };
    let cases: Vec<(String, &str)> = vec![
        (io(std::io::ErrorKind::ConnectionRefused, 111), "network:refused"),
        (io(std::io::ErrorKind::ConnectionReset, 104), "network:dropped"),
        (io(std::io::ErrorKind::BrokenPipe, 32), "network:dropped"),
        (io(std::io::ErrorKind::TimedOut, 110), "network:timeout"),
        (io(std::io::ErrorKind::StorageFull, 28), "disk:no_space"),
        (io(std::io::ErrorKind::ReadOnlyFilesystem, 30), "disk:read_only"),
        (io(std::io::ErrorKind::PermissionDenied, 13), "disk:permission"),
        (io(std::io::ErrorKind::NotFound, 2), "disk:not_found"),
        (io(std::io::ErrorKind::HostUnreachable, 113), "network:unreachable"),
        (io(std::io::ErrorKind::NetworkUnreachable, 101), "network:unreachable"),
        (io(std::io::ErrorKind::AddrInUse, 98), "config:address_in_use"),
        (io(std::io::ErrorKind::ResourceBusy, 16), "disk:busy"),
        ("I/O error during write the sidecar: No space left on device (os error 28)".into(), "disk:no_space"),
        ("I/O error during read chunk: Input/output error (os error 5)".into(), "disk:io"),
        ("failed to fill whole buffer".into(), "network:dropped"),
        ("io: Connection reset by peer (os error 104)".into(), "network:dropped"),
        ("io: Resource temporarily unavailable (os error 11)".into(), "network:timeout"),
        ("io: something else entirely".into(), "network:io"),
        ("protocol: closed during handshake".into(), "network:dropped"),
        ("invalid peer certificate: UnknownIssuer".into(), "network:tls"),
        ("received fatal alert: HandshakeFailure".into(), "network:tls"),
        ("SQLite is busy/locked during scan state (retried 5x)".into(), "slow:busy"),
        ("database error during fold: database is locked".into(), "slow:busy"),
        ("database error during open: database disk image is malformed".into(), "data:corruption"),
        ("database error during insert: UNIQUE constraint failed".into(), "disk:database"),
        ("integrity violation on node ab12: hash".into(), "data:integrity"),
        ("log chain broken at seq 4: expected a, got b".into(), "data:diverged"),
        ("canonical-encoding error in event at byte 3: short".into(), "data:encoding"),
        ("forbidden: write — no grant".into(), "auth:forbidden"),
        ("forbidden: this key was revoked".into(), "auth:revoked"),
        ("unknown_op: this daemon (proto 16) does not know the op".into(), "protocol:unknown_op"),
        ("protocol: expected Ready, got Info".into(), "protocol:unexpected"),
        ("expected value at line 1 column 1".into(), "protocol:malformed"),
        ("invalid input for level: nope".into(), "config:invalid"),
        ("region_not_held: this box holds no copy".into(), "data:not_held"),
        ("node not found: ab12".into(), "data:not_found"),
        ("ffprobe exited with status 1".into(), "external:tool"),
    ];
    for (text, want) in &cases {
        assert_eq!(from_text(text), Some(*want), "{text:?}");
        assert!(valid(want), "{want}");
    }
    assert_eq!(from_text("the moon is made of cheese"), None);
}

#[test]
fn event_names_and_the_site_come_before_the_text() {
    assert_eq!(from_event("pvfs.thread.panicked"), Some("internal:panic"));
    assert_eq!(from_event("pvfs.writer.checkpoint_slow"), Some("slow:held"));
    assert_eq!(from_event("pvfs.request.slow"), Some("slow:held"));
    assert_eq!(from_event("pvfs.tls.handshake_failed"), Some("network:tls"));
    assert_eq!(from_event("pvfs.job.failed"), None);
    let f = |name: &str, v: &str| pvfs_log::Field { name: name.into(), class: pvfs_log::Class::Meta, value: Value::Str(v.into()) };
    // The site's own word wins over the text.
    assert_eq!(classify("pvfs.job.failed", &[f("error", "connection refused"), f("error_kind", "disk:io")]), "disk:io");
    // The event over the text.
    assert_eq!(classify("pvfs.tls.handshake_failed", &[f("error", "connection reset by peer")]), "network:tls");
    // `reason` counts as the text.
    assert_eq!(classify("pvfs.job.failed", &[f("reason", "No space left on device")]), "disk:no_space");
    assert_eq!(classify("pvfs.job.failed", &[f("job", "watch")]), "other");
}

#[test]
fn a_warning_gets_its_kind_and_a_notice_gets_none() {
    let e = std::io::Error::from_raw_os_error(111);
    let recs = pvfs_log::capture(|| {
        pv_warn!("pvfs.job.failed", job = "watch", error = content(&e); "pvfsd: watch failed: {e}");
        pv_error!("pvfs.receive.no_space", path = content("/data/x.mkv"), error_kind = "disk:no_space"; "pvfsd: no space for /data/x.mkv");
        pv_warn!("pvfs.job.failed", job = "watch"; "pvfsd: watch failed");
        pv_info!("pvfs.job.recovered", job = "watch"; "pvfsd: watch ok");
    });
    assert_eq!(recs.len(), 4);
    assert_eq!(kind_of(&recs[0]).as_deref(), Some("network:refused"));
    assert_eq!(kind_of(&recs[1]).as_deref(), Some("disk:no_space"));
    assert_eq!(recs[1].fields.iter().filter(|f| f.name == "error_kind").count(), 1, "stated once, not added again");
    assert_eq!(kind_of(&recs[2]).as_deref(), Some("other"));
    assert_eq!(kind_of(&recs[3]), None, "info records carry no kind");
    // The kind survives `minimal`, where the error's text does not, and it
    // carries none of that text.
    let v = pvfs_log::render(&recs[0], pvfs_log::Privacy::Minimal, None);
    assert!(v.fields.iter().any(|f| f.name == "error_kind" && f.value.to_string() == "network:refused"), "{v:?}");
    assert!(v.fields.iter().all(|f| f.name != "error"), "{v:?}");
}

#[test]
fn the_vocabulary_is_closed() {
    for k in ["network", "network:refused", "slow:first_pass", "other"] {
        assert!(valid(k), "{k}");
    }
    for k in ["", "net:refused", "network:", "network:Refused", "network:refused path", "disk:/data", ":io"] {
        assert!(!valid(k), "{k:?}");
    }
}

#[test]
fn the_scan_holds_every_failure_call_to_a_kind() {
    let src = r#"
fn f() {
    pv_warn!("pvfs.a.no_text", job = "watch"; "x");
    pv_warn!("pvfs.a.has_error", job = "watch", error = content(&e); "x {e}");
    pv_error!("pvfs.a.has_reason", reason = r; "x");
    pv_warn!("pvfs.a.stated", path = content(p), error_kind = "disk:no_space"; "x");
    pv_warn!("pvfs.a.bad_kind", error_kind = "nonsense"; "x");
    pv_warn!("pvfs.a.computed", error_kind = kind_of(&e); "x");
    pv_error!("pvfs.a.panicked", thread = t; "x");
    pv_warn!(security failure "pvfs.a.sec_no_text", peer_addr = net(a), suppressed = n; "x; y");
    pv_info!("pvfs.a.info", job = "watch"; "x");
    pv_warn!("pvfs.a.nested", n = f(a, b), error = g(h(1), "a;b"); "x");
}
"#;
    let sources = vec![(PathBuf::from("x.rs"), src.to_string())];
    let uses = pvfs_log::registry::uses(&sources);
    assert_eq!(uses.len(), 10);
    let stated = uses.iter().find(|u| u.event == "pvfs.a.stated").unwrap();
    assert_eq!(stated.fields, vec!["path", "error_kind"]);
    assert_eq!(stated.error_kind.as_deref(), Some("disk:no_space"));
    let nested = uses.iter().find(|u| u.event == "pvfs.a.nested").unwrap();
    assert_eq!(nested.fields, vec!["n", "error"]);
    let problems = pvfs_log::registry::check_error_kinds(&uses);
    let named: Vec<&str> = ["pvfs.a.no_text", "pvfs.a.bad_kind", "pvfs.a.sec_no_text"].to_vec();
    assert_eq!(problems.len(), named.len(), "{problems:#?}");
    for (p, ev) in problems.iter().zip(named) {
        assert!(p.contains(ev), "{p}");
    }
}
