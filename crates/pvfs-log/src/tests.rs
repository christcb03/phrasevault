use super::*;
use crate::registry::{check, parse_table, stray_eprintlns, uses, valid_name, EventDef};
use std::path::PathBuf;

const KEY: [u8; 32] = [7u8; 32];

fn rec(line: &str, category: Category, fields: Vec<Field>) -> Record {
    let (component, msg) = split_component(line.to_string());
    Record {
        id: "0123456789abcdef0123456789abcdef".into(),
        seq: 3,
        ts_ms: 1_791_418_934_370,
        host: "mediabox".into(),
        service: "pvfsd".into(),
        pid: 4242,
        severity: Severity::Warning,
        event: "pvfs.job.failed".into(),
        category,
        outcome: None,
        component,
        via: None,
        msg,
        fields,
    }
}

fn f(name: &str, class: Class, v: &str) -> Field {
    Field { name: name.into(), class, value: Value::Str(v.into()) }
}

// ── the text a person reads is today's line, byte for byte ──────────────

/// Real lines from both repos (format strings with sample arguments).
const REAL: &[&str] = &[
    "pvfsd: listening on 0.0.0.0:7710 (transport pin 3f9a12bc)",
    "pvfsd: serving /home/chris/pvfs-mounts/media on /run/pvfs/media.sock",
    "pvfsd: shutting down (checkpointing)",
    "pvfsd: watch pass failed: I/O error during routed write: connection closed; retrying",
    "pvfsd: follow failed: I/O error during dial 192.168.1.30:7710: Connection refused; retrying",
    "pvfsd: health: 5512d034 (192.168.1.237:7710) not answering since 31000 — timed out",
    "pvfsd: the writer, last hour: 12 hold(s), 3.1s in all (longest 1.2s by fold); no waits; engine opens 4, read views 9, folds 2 (31 events), checkpoints 1",
    "pvfs: FENCED — a peer holds a longer log",
    "catalogue: 12 row(s) changed in Films",
    "mount: read-through cache — 25532 file(s) opened through, 0 kept whole, 1270341439644 bytes fetched; holding 5 entries, 851456000 bytes; evicted 0 (0 bytes)",
    "mount: 5512d034 is whole and verified (46276 bytes; stream mode keeps nothing)",
    "pvfs mount: unmounted /mnt/pvfs/view",
    "pvfs-companion: approval prompts: desktop; idle lock: 15m; audit: /Users/chris/.config/pvfs/companion.audit.jsonl",
    "pvosd: census — apps attached 3, supervised 4, desktops 1",
    "pvosd: started 'iac' (pid 31337)",
    "pvosd: app 'media' exited (exit status: 1)",
    "pvosd/web: websocket from a foreign origin refused: https://evil.example",
    "pvosd: ACME renewal failed (timeout) — retrying tomorrow",
    "iac: run 42 finished: exit 0",
    "no prefix on this line at all",
    "watch pass failed: three words before the colon is a sentence, not a prefix",
    ": starts with a colon",
];

#[test]
fn text_is_todays_line_for_real_lines() {
    for line in REAL {
        let r = rec(line, Category::System, vec![]);
        assert_eq!(&r.line(), line);
        assert_eq!(&render(&r, Privacy::Full, None).line(), line);
    }
}

#[test]
fn components_split_where_a_prefix_is() {
    let cases = [
        ("pvfsd: x: y", Some("pvfsd"), "x: y"),
        ("pvfs mount: x", Some("pvfs mount"), "x"),
        ("pvosd/app[iac] err: iac: hi", Some("pvosd/app[iac] err"), "iac: hi"),
        ("pvosd/pvfsd[/m/x] out: y", Some("pvosd/pvfsd[/m/x] out"), "y"),
        ("watch pass failed: x", None, "watch pass failed: x"),
        ("plain", None, "plain"),
        ("pvfsd:no space", None, "pvfsd:no space"),
    ];
    for (line, comp, msg) in cases {
        let (c, m) = split_component(line.to_string());
        assert_eq!(c.as_deref(), comp, "{line}");
        assert_eq!(m, msg, "{line}");
    }
}

// ── the macros ───────────────────────────────────────────────────────────

#[test]
fn macros_make_records() {
    let name = String::from("watch");
    let e = "I/O error: /srv/media/Films/Obsession (2026)/x.mkv: gone";
    let n: u64 = 3;
    let got = capture(|| {
        // The field takes `name` by move after the sentence borrowed it.
        pv_warn!("pvfs.job.failed", job = name, error = content(e), passes = n;
                 "pvfsd: {name} pass failed: {e}; retrying ({n})");
        pv_notice!("pvfs.serve.listening"; "pvfsd: listening on {}", "0.0.0.0:7710");
        pv_error!(security failure "pvfs.auth.refused", peer_addr = net("10.0.0.9:5555");
                  "pvfsd: refused 10.0.0.9:5555");
        pv_info!(audit "pvfs.acl.changed",; "pvfsd: acl changed");
    });
    assert_eq!(got.len(), 4);
    let w = &got[0];
    assert_eq!(w.severity, Severity::Warning);
    assert_eq!(w.event, "pvfs.job.failed");
    assert_eq!(w.category, Category::System);
    assert_eq!(w.outcome, None);
    assert_eq!(w.line(), format!("pvfsd: watch pass failed: {e}; retrying (3)"));
    assert_eq!(w.component.as_deref(), Some("pvfsd"));
    assert_eq!(w.fields[0], f("job", Class::Meta, "watch"));
    assert_eq!(w.fields[1], f("error", Class::Content, e));
    assert_eq!(w.fields[2], Field { name: "passes".into(), class: Class::Meta, value: Value::UInt(3) });
    assert!(got[1].fields.is_empty());
    assert_eq!(got[1].severity, Severity::Notice);
    assert_eq!(got[2].category, Category::Security);
    assert_eq!(got[2].outcome, Some(Outcome::Failure));
    assert_eq!(got[2].severity, Severity::Error);
    assert_eq!(got[3].category, Category::Audit);
    assert_eq!(w.id.len(), 32);
    assert!(got[1].seq > w.seq);
}

// ── privacy ──────────────────────────────────────────────────────────────

fn private_rec(category: Category) -> Record {
    rec(
        "pvfsd: delete of Films/Obsession (2026)/x.mkv by 02a1b2c3d4e5 from 10.1.2.3:4444 (chris@example.com): I/O error: Films/Obsession (2026)/x.mkv: gone",
        category,
        vec![
            f("path", Class::Content, "Films/Obsession (2026)/x.mkv"),
            f("principal", Class::Actor, "02a1b2c3d4e5"),
            f("peer_addr", Class::Net, "10.1.2.3:4444"),
            f("email", Class::Identity, "chris@example.com"),
            f("job", Class::Meta, "watch"),
            f("short", Class::Content, "abc"),
        ],
    )
}

#[test]
fn minimal_takes_personal_data_out_of_fields_and_sentence() {
    let r = private_rec(Category::System);
    let v = render(&r, Privacy::Minimal, Some(&KEY));
    let a = pseudonym(&KEY, 'a', "02a1b2c3d4e5");
    let h = pseudonym(&KEY, 'h', "Films/Obsession (2026)/x.mkv");
    assert_eq!(
        v.line(),
        format!("pvfsd: delete of ‹path› by {a} from ‹peer_addr› (‹email›): I/O error: ‹path›: gone")
    );
    let names: Vec<&str> = v.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["path", "principal", "job", "short"]);
    assert_eq!(v.fields[0].value, Value::Str(h));
    assert_eq!(v.fields[1].value, Value::Str(a.clone()));
    assert!(a.starts_with("a:") && a.len() == 14);
    // A short value is not hunted in the sentence, but is still not sent bare.
    assert_ne!(v.fields[3].value, Value::Str("abc".into()));
}

#[test]
fn minimal_keeps_addresses_on_security_events_only() {
    let v = render(&private_rec(Category::Security), Privacy::Minimal, Some(&KEY));
    assert!(v.line().contains("from 10.1.2.3:4444"));
    assert!(v.fields.iter().any(|f| f.name == "peer_addr"));
    assert!(v.line().contains("(‹email›)"));
}

#[test]
fn identified_adds_names_and_addresses_not_content() {
    let v = render(&private_rec(Category::System), Privacy::Identified, Some(&KEY));
    let line = v.line();
    assert!(line.contains("chris@example.com"));
    assert!(line.contains("10.1.2.3:4444"));
    assert!(!line.contains("Obsession"));
    assert!(!line.contains("02a1b2c3d4e5"));
}

#[test]
fn without_a_key_pseudonyms_become_stand_ins() {
    let v = render(&private_rec(Category::System), Privacy::Minimal, None);
    assert_eq!(
        v.line(),
        "pvfsd: delete of ‹path› by ‹principal› from ‹peer_addr› (‹email›): I/O error: ‹path›: gone"
    );
    let names: Vec<&str> = v.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["job"]);
}

#[test]
fn pseudonyms_are_keyed() {
    let other = [9u8; 32];
    assert_eq!(pseudonym(&KEY, 'a', "x1234"), pseudonym(&KEY, 'a', "x1234"));
    assert_ne!(pseudonym(&KEY, 'a', "x1234"), pseudonym(&other, 'a', "x1234"));
}

// ── encoders ─────────────────────────────────────────────────────────────

#[test]
fn json_round_trips() {
    let mut r = private_rec(Category::Security);
    r.outcome = Some(Outcome::Failure);
    r.via = Some("pvosd/app[iac] err".into());
    r.fields.push(Field { name: "n".into(), class: Class::Meta, value: Value::UInt(5) });
    r.fields.push(Field { name: "neg".into(), class: Class::Meta, value: Value::Int(-5) });
    r.fields.push(Field { name: "ok".into(), class: Class::Meta, value: Value::Bool(true) });
    let full = render(&r, Privacy::Full, None);
    let j = to_json(&r, &full);
    assert!(j.starts_with("{\"v\":1,\"id\":\"0123456789abcdef0123456789abcdef\",\"seq\":3,\"ts\":\"2026-10-08T00:22:14.370Z\""));
    assert!(j.contains("\"classes\":{\"path\":\"content\",\"principal\":\"actor\",\"peer_addr\":\"net\",\"email\":\"identity\",\"short\":\"content\"}"));
    let back = parse_json(&j).expect("parses");
    assert_eq!(back, r);
}

#[test]
fn json_that_is_not_ours_is_not_a_record() {
    assert!(parse_json("plain line").is_none());
    assert!(parse_json("{\"v\":2,\"id\":\"x\"}").is_none());
    assert!(parse_json("{\"level\":\"info\"}").is_none());
    assert!(parse_json("{not json").is_none());
}

#[test]
fn logfmt_quotes_what_needs_it() {
    let r = rec("pvfsd: a \"quoted\" = thing", Category::System, vec![f("event", Class::Meta, "x y"), f("job", Class::Meta, "watch")]);
    let s = to_logfmt(&r, &render(&r, Privacy::Full, None));
    assert_eq!(
        s,
        "ts=2026-10-08T00:22:14.370Z severity=warning event=pvfs.job.failed service=pvfsd component=pvfsd msg=\"a \\\"quoted\\\" = thing\" f_event=\"x y\" job=watch id=0123456789abcdef0123456789abcdef"
    );
}

#[test]
fn journal_fields_and_datagram() {
    let r = rec("pvfsd: two\nlines", Category::System, vec![f("peer_addr", Class::Net, "1.2.3.4:5"), f("event", Class::Meta, "x")]);
    let v = render(&r, Privacy::Full, None);
    let fields = journal::fields(&r, &v, "pvfsd");
    let get = |k: &str| fields.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("MESSAGE"), Some("pvfsd: two\nlines"));
    assert_eq!(get("PRIORITY"), Some("4"));
    assert_eq!(get("SYSLOG_IDENTIFIER"), Some("pvfsd"));
    assert_eq!(get("PV_EVENT"), Some("pvfs.job.failed"));
    assert_eq!(get("PV_SCHEMA"), Some("1"));
    assert_eq!(get("PV_PEER_ADDR"), Some("1.2.3.4:5"));
    assert_eq!(get("PV_F_EVENT"), Some("x"));
    let d = journal::datagram(&[("A".into(), "x".into()), ("B".into(), "1\n2".into())]);
    let mut want = b"A=x\nB\n".to_vec();
    want.extend_from_slice(&3u64.to_le_bytes());
    want.extend_from_slice(b"1\n2\n");
    assert_eq!(d, want);
    assert_eq!(journal::field_name("a-b.c"), "PV_A_B_C");
    assert_eq!(journal::field_name(&"x".repeat(100)).len(), 64);
}

#[test]
fn a_record_too_big_for_a_datagram_is_refused() {
    let big = "x".repeat(journal::MAX_DATAGRAM + 1);
    assert!(journal::send(&[("MESSAGE".into(), big)]).is_err());
}

// ── time ─────────────────────────────────────────────────────────────────

#[test]
fn timestamps() {
    for (ms, s) in [
        (0, "1970-01-01T00:00:00.000Z"),
        (1_791_418_934_370, "2026-10-08T00:22:14.370Z"),
        (951_782_400_123, "2000-02-29T00:00:00.123Z"),
        (4_102_444_799_999, "2099-12-31T23:59:59.999Z"),
    ] {
        assert_eq!(format_ts(ms), s);
        assert_eq!(parse_ts(s), Some(ms));
    }
    // Another zone's record: the NAS writes -04:00.
    assert_eq!(parse_ts("2026-10-07T20:22:14.370-04:00"), Some(1_791_418_934_370));
    assert_eq!(parse_ts("2026-10-08T00:22:14Z"), Some(1_791_418_934_000));
    assert_eq!(parse_ts("2026-10-08T00:22:14.370123Z"), Some(1_791_418_934_370));
    assert_eq!(parse_ts("2026-13-08T00:22:14Z"), None);
    assert_eq!(parse_ts("yesterday"), None);
}

// ── settings ─────────────────────────────────────────────────────────────

#[test]
fn names_parse() {
    assert_eq!(Severity::parse("WARN"), Some(Severity::Warning));
    assert_eq!(Severity::parse("bogus"), None);
    assert!(Severity::Error < Severity::Info);
    assert_eq!(Format::parse("json"), Some(Format::Json));
    assert_eq!(Format::parse(""), Some(Format::Auto));
    assert_eq!(Privacy::parse("Minimal"), Some(Privacy::Minimal));
}

#[test]
fn keys_read_raw_or_hex() {
    let d = tempfile::tempdir().unwrap();
    let raw = d.path().join("raw");
    std::fs::write(&raw, [5u8; 32]).unwrap();
    assert_eq!(read_key(&raw).unwrap(), [5u8; 32]);
    let hex = d.path().join("hex");
    std::fs::write(&hex, format!("{}\n", "0a".repeat(32))).unwrap();
    assert_eq!(read_key(&hex).unwrap(), [10u8; 32]);
    let bad = d.path().join("bad");
    std::fs::write(&bad, "short").unwrap();
    assert!(read_key(&bad).is_err());
}

// ── relaying a child's lines ─────────────────────────────────────────────

#[test]
fn relayed_lines_keep_a_childs_record() {
    let child = rec("iac: run 42 failed", Category::System, vec![f("path", Class::Content, "/srv/x")]);
    let line = to_json(&child, &render(&child, Privacy::Full, None));
    let r = relayed(&line, "pvosd/app[iac] err", "app:iac", "pvos.app.output", vec![]);
    assert_eq!(r.event, "pvfs.job.failed");
    assert_eq!(r.severity, Severity::Warning);
    assert_eq!(r.service, "app:iac");
    assert_eq!(r.fields[0].class, Class::Content);
    assert_eq!(r.line(), "pvosd/app[iac] err: iac: run 42 failed");

    let raw = relayed("thread 'main' panicked at src/main.rs:3:5", "pvosd/app[iac] err", "app:iac", "pvos.app.output", vec![]);
    assert_eq!(raw.event, "pvos.app.output");
    assert_eq!(raw.severity, Severity::Info);
    assert_eq!(raw.line(), "pvosd/app[iac] err: thread 'main' panicked at src/main.rs:3:5");

    // A forest's mount path in `via` comes out at minimal when it is a field.
    let fr = relayed(
        "pvfsd: listening on 0.0.0.0:7710",
        "pvosd/pvfsd[/home/chris/mounts/family] err",
        "pvfsd",
        "pvos.forest.output",
        vec![content("/home/chris/mounts/family").to_field("mount")],
    );
    assert_eq!(fr.line(), "pvosd/pvfsd[/home/chris/mounts/family] err: pvfsd: listening on 0.0.0.0:7710");
    assert_eq!(render(&fr, Privacy::Minimal, None).line(), "pvosd/pvfsd[‹mount›] err: pvfsd: listening on 0.0.0.0:7710");
}

// ── the registry check ───────────────────────────────────────────────────

#[test]
fn event_names() {
    assert!(valid_name("pvfs.job.failed"));
    assert!(valid_name("pvos.app.started_2"));
    assert!(!valid_name("pvfs.job"));
    assert!(!valid_name("pvfs.Job.failed"));
    assert!(!valid_name("pvfs..failed"));
}

#[test]
fn registry_finds_what_is_wrong() {
    let md = "intro\n\n| Event | Severity | Category | Meaning |\n|---|---|---|---|\n\
              | `pvfs.job.failed` | warning | system | A pass failed. |\n\
              | `pvfs.auth.refused` | warning | security | A request was refused. |\n\
              | `pvfs.old.gone` | info | system | Nobody logs this. |\n\
              | `pvfs.job.failed` | warning | system | twice |\n";
    let defs: Vec<EventDef> = parse_table(md).unwrap();
    assert_eq!(defs.len(), 4);
    let src = r#"
fn a() {
    pv_warn!("pvfs.job.failed", job = "w"; "pvfsd: x");
    pv_warn!(system "pvfs.auth.refused"; "pvfsd: y");   // wrong category
    // pv_info!("pvfs.commented.out"; "z");
    pv_info!(
        "pvfs.not.listed"; "pvfsd: z");
    eprintln!("left over");
    eprintln!("allowed"); // pv-log: allow
}
"#;
    let srcs = vec![(PathBuf::from("a.rs"), src.to_string())];
    let u = uses(&srcs);
    assert_eq!(u.len(), 3);
    assert_eq!(u[2].event, "pvfs.not.listed");
    assert_eq!(u[2].line, 6);
    let p = check(&defs, &u, &srcs, "pvfs.");
    assert!(p.iter().any(|m| m.contains("listed twice: pvfs.job.failed")), "{p:?}");
    assert!(p.iter().any(|m| m.contains("listed but never logged: pvfs.old.gone")), "{p:?}");
    assert!(p.iter().any(|m| m.contains("pvfs.not.listed is not in the event list")), "{p:?}");
    assert!(p.iter().any(|m| m.contains("logged as system but listed as security")), "{p:?}");
    assert_eq!(p.len(), 4, "{p:?}");
    let strays = stray_eprintlns(&srcs);
    assert_eq!(strays.len(), 1);
    assert_eq!(strays[0].1, 8);
}

// ── D222b: rate limits and the global capture ───────────────────────────

#[test]
fn the_limit_lets_ten_a_minute_through_and_counts_the_rest() {
    let mut l = Limiter::new();
    for i in 0..10 {
        assert_eq!(l.check(1_000 + i, "pvfs.auth.refused", "10.0.0.9"), Some(0));
    }
    for i in 0..20 {
        assert_eq!(l.check(2_000 + i, "pvfs.auth.refused", "10.0.0.9"), None);
    }
    // Another key and another event are not held back.
    assert_eq!(l.check(3_000, "pvfs.auth.refused", "10.0.0.10"), Some(0));
    assert_eq!(l.check(3_000, "pvfs.access.denied", "10.0.0.9"), Some(0));
    // The next minute: the first one says how many were dropped.
    assert_eq!(l.check(61_001, "pvfs.auth.refused", "10.0.0.9"), Some(20));
    assert_eq!(l.check(61_002, "pvfs.auth.refused", "10.0.0.9"), Some(0));
}

#[test]
fn the_limit_forgets_the_oldest_key_at_its_cap() {
    let mut l = Limiter::new();
    for i in 0..(limit::MAX_KEYS as u64 + 50) {
        l.check(i, "pvfs.auth.refused", &format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255));
    }
    assert_eq!(l.keys(), limit::MAX_KEYS);
}

#[test]
fn the_global_capture_sees_other_threads() {
    let cap = testing::GlobalCapture::start();
    std::thread::spawn(|| {
        pv_warn!("pvfs.test.global_capture", marker = "d222b-gc-1"; "pvfsd: from another thread");
    })
    .join()
    .unwrap();
    let mine: Vec<Record> = cap
        .events("pvfs.test.global_capture")
        .into_iter()
        .filter(|r| r.fields.iter().any(|f| f.value == Value::Str("d222b-gc-1".into())))
        .collect();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].line(), "pvfsd: from another thread");
}

#[test]
fn thread_context_fields_ride_along() {
    let got = capture(|| {
        set_thread_context(vec![net("192.0.2.7:5555").to_field("peer_addr")]);
        pv_warn!(security failure "pvos.signin.refused"; "pvosd: browser sign-in refused: nope");
        pv_info!("pvos.web.x", peer_addr = net("10.9.9.9:1"); "pvosd/web: own address wins");
        clear_thread_context();
        pv_info!("pvos.web.y"; "pvosd/web: none after clearing");
    });
    // PVOS D229: a warning also says what kind of failure it is.
    assert_eq!(got[0].fields, vec![net("192.0.2.7:5555").to_field("peer_addr"), "other".to_field("error_kind")]);
    assert_eq!(got[1].fields, vec![net("10.9.9.9:1").to_field("peer_addr")]);
    assert!(got[2].fields.is_empty());
}
