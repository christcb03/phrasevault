//! D222d — formats, transports against in-test receivers, the spool through
//! a sender, health, the install path.

use super::*;
use crate::{content, identity, net, render, Category, Class, Field, Outcome, Privacy, Record, ToField, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

fn rec(event: &str, line: &str, category: Category, fields: Vec<Field>) -> Record {
    let mut r = Record::now(Severity::Warning, event, line.to_string());
    r.category = category;
    r.fields = fields;
    r.host = "mediabox".into();
    r.service = "pvfsd".into();
    r.ts_ms = 1_791_418_934_370;
    r
}

fn dest(kind: Kind) -> Destination {
    Destination {
        name: "t".into(),
        enabled: true,
        kind,
        url: None,
        address: None,
        transport: None,
        format: None,
        index: None,
        sourcetype: None,
        header: None,
        privacy: "full".into(),
        min_severity: "info".into(),
        categories: vec![],
        services: vec![],
        tls: TlsSettings::default(),
        secret: None,
        labels: Default::default(),
        doc_ids: false,
        spool_mb: 1,
    }
}

fn mk_dest(cfg: Destination, token: Option<&str>, dir: &Path) -> Arc<sender::Dest> {
    Arc::new(sender::Dest {
        cfg,
        token: token.map(str::to_string),
        key: Some([3u8; 32]),
        product: "PVFS".into(),
        version: "1.4-test".into(),
        spool: Mutex::new(Spool::open(dir, 1 << 20).unwrap()),
        health: Mutex::new(Health::default()),
        stop: AtomicBool::new(false),
        started_ms: crate::time::now_ms(),
        failing_after_ms: 0,
    })
}

// ── formats ──────────────────────────────────────────────────────────────

#[test]
fn rfc5424_escapes_its_structured_data() {
    let r = rec(
        "pvfs.access.denied",
        "pvfsd: ls refused for public from 10.0.0.9:5555: no \"read\" ] here \\",
        Category::Security,
        vec![Field { name: "reason".into(), class: Class::Meta, value: Value::Str("a\"b]c\\d".into()) }],
    );
    let v = render(&r, Privacy::Full, None);
    let m = format::rfc5424(&r, &v, &v.line(), true);
    // authpriv (10) * 8 + warning (4) = 84
    assert!(m.starts_with("<84>1 2026-10-08T00:22:14.370Z mediabox pvfsd "), "{m}");
    assert!(m.contains(" pvfs.access.denied [pvlog@32473 event=\"pvfs.access.denied\" category=\"security\""), "{m}");
    assert!(m.contains("reason=\"a\\\"b\\]c\\\\d\"]"), "{m}");
    assert!(m.ends_with("pvfsd: ls refused for public from 10.0.0.9:5555: no \"read\" ] here \\"));
    // MSGID is at most 32 characters.
    let long = rec("pvfs.authority.recovery_key_registered", "x", Category::Audit, vec![]);
    let lv = render(&long, Privacy::Full, None);
    assert!(format::rfc5424(&long, &lv, "x", false).contains(" pvfs.authority.recovery_key_regi - x"));
}

#[test]
fn cef_escapes_header_and_extension() {
    let mut r = rec(
        "pvfs.access.denied",
        "pvfsd: a|b = c\nd",
        Category::Security,
        vec![
            net("10.0.0.9:5555").to_field("peer_addr"),
            Field { name: "principal".into(), class: Class::Actor, value: Value::Str("key:02ab".into()) },
            Field { name: "op".into(), class: Class::Meta, value: Value::Str("ls".into()) },
        ],
    );
    r.outcome = Some(Outcome::Failure);
    let v = render(&r, Privacy::Full, None);
    let c = format::cef(&r, &v, "PVFS", "1.4|x");
    assert!(c.starts_with("CEF:0|PhraseVault|PVFS|1.4\\|x|pvfs.access.denied|pvfsd: a\\|b = c d|5|"), "{c}");
    assert!(c.contains(" src=10.0.0.9 spt=5555 "), "{c}");
    assert!(c.contains(" suser=key:02ab "), "{c}");
    assert!(c.contains(" cs1Label=op cs1=ls "), "{c}");
    assert!(c.contains(" outcome=failure "), "{c}");
    assert!(c.ends_with(" msg=pvfsd: a|b \\= c\\nd"), "{c}");
}

#[test]
fn hec_and_loki_bodies() {
    let r = rec("pvfs.job.failed", "pvfsd: watch failed", Category::System, vec![]);
    let v = render(&r, Privacy::Full, None);
    let h = format::hec_event(&r, &v, "pvfs:json", Some("main"));
    let j: serde_json::Value = serde_json::from_str(&h).unwrap();
    assert_eq!(j["time"].as_f64().unwrap(), 1_791_418_934.37);
    assert_eq!(j["sourcetype"], "pvfs:json");
    assert_eq!(j["index"], "main");
    assert_eq!(j["event"]["event"], "pvfs.job.failed");
    let s = rec("pvfs.auth.refused", "pvfsd: refused", Category::Security, vec![]);
    let sv = render(&s, Privacy::Full, None);
    let body = format::loki_body(&[(&r, v.clone()), (&s, sv.clone())], &Default::default());
    let j: serde_json::Value = serde_json::from_str(&body).unwrap();
    let streams = j["streams"].as_array().unwrap();
    assert_eq!(streams.len(), 2, "system and security lines are separate streams");
    let sec = streams.iter().find(|s| s["stream"]["category"] == "security").unwrap();
    assert_eq!(sec["stream"]["job"], "pvlog");
    assert_eq!(sec["values"][0][0], "1791418934370000000");
    assert_eq!(sec["values"][0][1], "pvfsd: refused");
    assert_eq!(sec["values"][0][2]["event"], "pvfs.auth.refused");
    // PVOS D224 — a destination's own labels go on every stream.
    let extra: std::collections::BTreeMap<String, String> = [("env".to_string(), "prod".to_string())].into();
    let j: serde_json::Value = serde_json::from_str(&format::loki_body(&[(&r, v), (&s, sv)], &extra)).unwrap();
    let streams = j["streams"].as_array().unwrap();
    assert_eq!(streams.len(), 2);
    for st in streams {
        assert_eq!(st["stream"]["env"], "prod", "{st}");
        assert_eq!(st["stream"]["job"], "pvlog");
        assert!(st["stream"]["host"].is_string() && st["stream"]["level"].is_string());
    }
    // PVOS D229 — a failure's kind is structured metadata, kept at `minimal`
    // (where its error text is not); a record without one has none.
    let mut k = rec("pvfs.job.failed", "pvfsd: watch failed: refused", Category::System, vec![]);
    k.fields.push(crate::content("connection refused").to_field("error"));
    k.fields.push("network:refused".to_field("error_kind"));
    let kv = render(&k, Privacy::Minimal, None);
    let j: serde_json::Value = serde_json::from_str(&format::loki_body(&[(&k, kv), (&r, render(&r, Privacy::Full, None))], &Default::default())).unwrap();
    let vals: Vec<&serde_json::Value> = j["streams"].as_array().unwrap().iter().flat_map(|s| s["values"].as_array().unwrap()).collect();
    assert_eq!(vals[0][2]["error_kind"], "network:refused", "{j}");
    assert!(vals[1][2].get("error_kind").is_none(), "{j}");
}

/// PVOS D224 — labels: Loki only, label names, never one PVFS sets.
#[test]
fn a_loki_destinations_labels_are_checked() {
    let mut d = dest(Kind::Loki);
    d.url = Some("http://loki.example:3100".into());
    d.labels = [("env".to_string(), "prod".to_string()), ("site".to_string(), "home".to_string())].into();
    assert!(d.problems().is_empty(), "{:?}", d.problems());
    for (k, v, why) in [
        ("job", "x", "set by PVFS"),
        ("category", "x", "set by PVFS"),
        ("__name", "x", "not a label name"),
        ("9lives", "x", "not a label name"),
        ("bad-name", "x", "not a label name"),
        ("env", "", "1 to 128"),
    ] {
        let mut b = d.clone();
        b.labels = [(k.to_string(), v.to_string())].into();
        assert!(b.problems().iter().any(|p| p.contains(why)), "{k}={v}: {:?}", b.problems());
    }
    let mut hec = dest(Kind::SplunkHec);
    hec.url = Some("https://splunk.example:8088".into());
    hec.labels = [("env".to_string(), "prod".to_string())].into();
    assert!(hec.problems().iter().any(|p| p.contains("loki destination only")), "{:?}", hec.problems());
    // A file written with labels reads back with them; one without has none.
    let j = serde_json::to_string(&d).unwrap();
    assert!(j.contains("\"labels\":{\"env\":\"prod\",\"site\":\"home\"}"), "{j}");
    let back: Destination = serde_json::from_str(&j).unwrap();
    assert_eq!(back.labels, d.labels);
    assert!(!serde_json::to_string(&dest(Kind::Loki)).unwrap().contains("labels"));
}

/// PVOS D224 — the sender pushes the labels to Loki.
#[test]
fn the_loki_sender_pushes_the_destinations_labels() {
    let d = tempfile::tempdir().unwrap();
    let r = rec("pvfs.tls.handshake_failed", "pvfsd: TLS handshake failed", Category::Security, vec![]);
    let (url, t) = http_server(vec![(204, "")]);
    let mut l = dest(Kind::Loki);
    l.url = Some(url);
    l.labels = [("env".to_string(), "prod".to_string())].into();
    let ld = mk_dest(l, None, &d.path().join("l"));
    sender::deliver(&ld, std::slice::from_ref(&r)).unwrap();
    let got = t.join().unwrap();
    assert!(got[0].0.starts_with("POST /loki/api/v1/push HTTP/1.1"), "{}", got[0].0);
    let j: serde_json::Value = serde_json::from_str(&got[0].1).unwrap();
    assert_eq!(j["streams"][0]["stream"]["env"], "prod");
    assert_eq!(j["streams"][0]["stream"]["category"], "security");
}

#[test]
fn a_minimal_destination_never_sees_a_path_or_a_name() {
    let r = rec(
        "pvfs.mount.deleted",
        "mount: delete of Films/Obsession (2026)/x.mkv by chris@example.com",
        Category::System,
        vec![content("Films/Obsession (2026)/x.mkv").to_field("path"), identity("chris@example.com").to_field("email")],
    );
    let v = render(&r, Privacy::Minimal, Some(&[3u8; 32]));
    for out in [
        format::rfc5424(&r, &v, &v.line(), true),
        format::cef(&r, &v, "PVFS", "1"),
        format::hec_event(&r, &v, "pvfs:json", None),
        format::ndjson(&[(&r, v.clone())]),
    ] {
        assert!(!out.contains("Obsession") && !out.contains("chris@"), "{out}");
    }
}

// ── transports, against in-test receivers ────────────────────────────────

fn read_frames(mut s: impl Read) -> Vec<String> {
    let mut all = Vec::new();
    let _ = s.read_to_end(&mut all);
    let mut out = Vec::new();
    let mut i = 0;
    while i < all.len() {
        let sp = all[i..].iter().position(|b| *b == b' ').unwrap();
        let n: usize = std::str::from_utf8(&all[i..i + sp]).unwrap().parse().unwrap();
        out.push(String::from_utf8(all[i + sp + 1..i + sp + 1 + n].to_vec()).unwrap());
        i += sp + 1 + n;
    }
    out
}

#[test]
fn syslog_over_tcp_and_udp() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let t = std::thread::spawn(move || read_frames(l.accept().unwrap().0));
    syslog::send(&addr, SyslogTransport::Tcp, &TlsSettings::default(), &["one".into(), "two 2".into()]).unwrap();
    assert_eq!(t.join().unwrap(), vec!["one".to_string(), "two 2".to_string()]);

    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    let uaddr = u.local_addr().unwrap().to_string();
    syslog::send(&uaddr, SyslogTransport::Udp, &TlsSettings::default(), &["<14>1 - - - - - - hi".into()]).unwrap();
    let mut buf = [0u8; 9000];
    let (n, _) = u.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"<14>1 - - - - - - hi");
}

fn tls_server() -> (TcpListener, Arc<rustls::ServerConfig>, String) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let der = ck.cert.der().to_vec();
    let pin: String = {
        use sha2::Digest;
        sha2::Sha256::digest(&der).iter().map(|b| format!("{b:02x}")).collect()
    };
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![rustls::pki_types::CertificateDer::from(der)], key)
        .unwrap();
    (TcpListener::bind("127.0.0.1:0").unwrap(), Arc::new(cfg), pin)
}

#[test]
fn syslog_over_tls_needs_the_right_certificate() {
    let (l, cfg, pin) = tls_server();
    let addr = l.local_addr().unwrap().to_string();
    let t = std::thread::spawn(move || {
        let mut out = Vec::new();
        for _ in 0..2 {
            let (s, _) = l.accept().unwrap();
            let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, s);
            let mut all = Vec::new();
            let _ = tls.read_to_end(&mut all);
            out.push(all);
        }
        out
    });
    let pinned = TlsSettings { ca_file: None, pin_sha256: Some(pin) };
    syslog::send(&addr, SyslogTransport::Tls, &pinned, &["secure".into()]).unwrap();
    // The public roots do not vouch for a self-signed certificate.
    assert!(syslog::send(&addr, SyslogTransport::Tls, &TlsSettings::default(), &["nope".into()]).is_err());
    let got = t.join().unwrap();
    assert_eq!(read_frames(&got[0][..]), vec!["secure".to_string()]);
    assert!(got[1].is_empty(), "nothing reached the server over the unverified connection");
}

/// A tiny HTTP receiver: answers each request with the next of `answers`
/// (status, body) and keeps (head, body).
fn http_server(answers: Vec<(u16, &'static str)>) -> (String, std::thread::JoinHandle<Vec<(String, String)>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let t = std::thread::spawn(move || {
        let mut got = Vec::new();
        for (code, body) in answers {
            let (mut s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut head = String::new();
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                if line.to_ascii_lowercase().starts_with("content-length:") {
                    len = line[15..].trim().parse().unwrap();
                }
                if line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).unwrap();
            let _ = write!(s, "HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            got.push((head, String::from_utf8(b).unwrap()));
        }
        got
    });
    (url, t)
}

#[test]
fn hec_sends_its_token_and_reads_the_answer() {
    let (url, t) = http_server(vec![(200, "{\"text\":\"Success\",\"code\":0}"), (403, "{\"text\":\"Invalid token\",\"code\":4}")]);
    let mut cfg = dest(Kind::SplunkHec);
    cfg.url = Some(url);
    cfg.index = Some("main".into());
    let d = tempfile::tempdir().unwrap();
    let dd = mk_dest(cfg, Some("tok-123"), d.path());
    let r = rec("pvfs.job.failed", "pvfsd: x", Category::System, vec![]);
    sender::deliver(&dd, std::slice::from_ref(&r)).unwrap();
    let e = sender::deliver(&dd, &[r]).unwrap_err();
    assert!(e.contains("403"), "{e}");
    let got = t.join().unwrap();
    assert!(got[0].0.starts_with("POST /services/collector/event HTTP/1.1"), "{}", got[0].0);
    assert!(got[0].0.contains("Authorization: Splunk tok-123"));
    let ev: serde_json::Value = serde_json::from_str(&got[0].1).unwrap();
    assert_eq!(ev["index"], "main");
    assert_eq!(ev["event"]["event"], "pvfs.job.failed");
}

#[test]
fn the_spool_delivers_in_order_after_the_receiver_comes_back_and_says_so() {
    let cap = crate::testing::GlobalCapture::start();
    // First answer fails, then two succeed.
    let (url, t) = http_server(vec![(500, "down"), (200, "ok"), (200, "ok")]);
    let mut cfg = dest(Kind::HttpsJson);
    cfg.name = "spooltest".into();
    cfg.url = Some(url);
    let d = tempfile::tempdir().unwrap();
    let dd = mk_dest(cfg, Some("s3cret"), d.path());
    for i in 0..3 {
        dd.offer(&rec("pvfs.job.failed", &format!("pvfsd: number {i}"), Category::System, vec![]));
    }
    let runner = Arc::clone(&dd);
    let th = std::thread::spawn(move || sender::run(runner));
    let deadline = Instant::now() + Duration::from_secs(20);
    while dd.health().sent < 3 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    // One more after the first batch went: a second request.
    dd.offer(&rec("pvfs.job.failed", "pvfsd: number 3", Category::System, vec![]));
    while dd.health().sent < 4 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    dd.stop.store(true, Ordering::Relaxed);
    th.join().unwrap();
    let got = t.join().unwrap();
    assert_eq!(dd.health().sent, 4);
    assert!(got[1].0.contains("Authorization: Bearer s3cret"));
    let lines: Vec<String> = got[1].1.lines().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["msg"].as_str().unwrap().to_string()).collect();
    assert_eq!(lines, vec!["number 0", "number 1", "number 2"]);
    assert!(got[2].1.contains("number 3"));
    // failing_after_ms = 0: the first failure was reported, the success after it too.
    assert!(cap.events("pvfs.log.destination_failing").iter().any(|r| r.fields.iter().any(|f| f.value == Value::Str("spooltest".into()))));
    assert!(cap.events("pvfs.log.destination_recovered").iter().any(|r| r.fields.iter().any(|f| f.value == Value::Str("spooltest".into()))));
}

#[test]
fn a_destination_never_gets_its_own_failure_and_filters_apply() {
    let mut cfg = dest(Kind::HttpsJson);
    cfg.name = "x".into();
    cfg.categories = vec!["security".into()];
    cfg.min_severity = "warning".into();
    let own = rec("pvfs.log.destination_failing", "pvfs-log: x failed", Category::Security, vec![crate::ToField::to_field("x", "destination")]);
    assert!(!cfg.takes(&own));
    let sec = rec("pvfs.auth.refused", "pvfsd: refused", Category::Security, vec![]);
    assert!(cfg.takes(&sec));
    let sys = rec("pvfs.job.failed", "pvfsd: failed", Category::System, vec![]);
    assert!(!cfg.takes(&sys));
    let mut info = sec.clone();
    info.severity = Severity::Info;
    assert!(!cfg.takes(&info));
}

#[test]
fn config_parses_and_says_what_is_wrong() {
    let ok = r#"{"v":1,"destinations":[
        {"name":"logs","type":"loki","url":"http://192.168.1.83:3100","privacy":"full"},
        {"name":"siem","type":"syslog","address":"siem.corp:6514","format":"cef"},
        {"name":"splunk","type":"splunk_hec","url":"https://splunk:8088","secret":"splunk.token","tls":{"pin_sha256":"ab"}}]}"#;
    let c = ShipConfig::parse(ok).unwrap();
    assert_eq!(c.destinations[1].privacy, "minimal", "minimal by default");
    assert_eq!(c.destinations[1].syslog_transport(), SyslogTransport::Tls, "tls by default");
    assert!(c.destinations[0].problems().is_empty());
    assert!(c.destinations[1].problems().is_empty());
    assert!(c.destinations[2].problems().iter().any(|p| p.contains("pin_sha256")));
    assert!(ShipConfig::parse(r#"{"v":2}"#).is_err());
    assert!(ShipConfig::parse(r#"{"v":1,"destinations":[{"name":"a","type":"loki","url":"http://x"},{"name":"a","type":"loki","url":"http://y"}]}"#).is_err());
    let back = ShipConfig::parse(&c.to_text()).unwrap();
    assert_eq!(back, c);
}

#[test]
fn whois_finds_the_member() {
    let key = [9u8; 32];
    let p = crate::pseudonym(&key, 'a', "key:02cafe");
    assert_eq!(whois(&key, &p, ["key:0200", "key:02cafe", "chris"]), vec!["key:02cafe"]);
}

// ── D222e: LEEF, RFC 3164, GELF, ECS / _bulk, OCSF, OTLP ────────────────

fn refusal() -> Record {
    let mut r = rec(
        "pvfs.access.denied",
        "pvfsd: ls refused for key:02ab from 10.0.0.9:5555: access denied",
        Category::Security,
        vec![
            Field { name: "op".into(), class: Class::Meta, value: Value::Str("ls".into()) },
            Field { name: "principal".into(), class: Class::Actor, value: Value::Str("key:02ab".into()) },
            net("10.0.0.9:5555").to_field("peer_addr"),
            Field { name: "id".into(), class: Class::Meta, value: Value::Str("clash".into()) },
        ],
    );
    r.outcome = Some(Outcome::Failure);
    r
}

#[test]
fn leef_and_rfc3164() {
    let r = refusal();
    let v = render(&r, Privacy::Full, None);
    let l = format::leef(&r, &v, "PVFS", "1.4");
    assert!(l.starts_with("LEEF:2.0|PhraseVault|PVFS|1.4|pvfs.access.denied|x09|devTime=1791418934370\tsev=5\tcat=security\t"), "{l}");
    assert!(l.contains("\tsrc=10.0.0.9\tsrcPort=5555\t"), "{l}");
    assert!(l.contains("\tusrName=key:02ab\t"), "{l}");
    assert!(l.contains("\tpv_op=ls\t"), "{l}");
    assert!(!l.contains('\n'));
    let b = format::rfc3164(&r, &v.line());
    // authpriv (10) * 8 + warning (4); 2026-10-08 00:22:14 UTC; the day space-padded.
    assert_eq!(b, format!("<84>Oct  8 00:22:14 mediabox pvfsd[{}]: pvfsd: ls refused for key:02ab from 10.0.0.9:5555: access denied", r.pid));
}

#[test]
fn gelf_documents() {
    let r = refusal();
    let v = render(&r, Privacy::Full, None);
    let g: serde_json::Value = serde_json::from_str(&format::gelf(&r, &v)).unwrap();
    assert_eq!(g["version"], "1.1");
    assert_eq!(g["host"], "mediabox");
    assert_eq!(g["level"], 4);
    assert_eq!(g["timestamp"].as_f64().unwrap(), 1_791_418_934.37);
    assert_eq!(g["_event"], "pvfs.access.denied");
    assert_eq!(g["_outcome"], "failure");
    assert_eq!(g["_op"], "ls");
    assert_eq!(g["_f_id"], "clash", "GELF reserves _id");
    assert!(g.get("_id").is_none());
    // Too big for one datagram: the sentence is cut and the extras go.
    let mut big = r.clone();
    big.fields.push(Field { name: "huge".into(), class: Class::Meta, value: Value::Str("x".repeat(20_000)) });
    let bv = render(&big, Privacy::Full, None);
    let small = format::gelf_udp(&big, &bv, 8192);
    assert!(small.len() <= 8192);
    let g: serde_json::Value = serde_json::from_str(&small).unwrap();
    assert!(g.get("_huge").is_none());
}

#[test]
fn ecs_and_bulk() {
    let r = refusal();
    let v = render(&r, Privacy::Full, None);
    let e: serde_json::Value = serde_json::from_str(&format::ecs(&r, &v)).unwrap();
    assert_eq!(e["@timestamp"], "2026-10-08T00:22:14.370Z");
    assert_eq!(e["event"]["action"], "pvfs.access.denied");
    assert_eq!(e["event"]["kind"], "alert");
    assert_eq!(e["event"]["category"][0], "iam");
    assert_eq!(e["event"]["type"][0], "denied");
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(e["log"]["level"], "warning");
    assert_eq!(e["source"]["ip"], "10.0.0.9");
    assert_eq!(e["source"]["port"], 5555);
    assert_eq!(e["user"]["id"], "key:02ab");
    assert_eq!(e["labels"]["op"], "ls");
    let mut auth = refusal();
    auth.event = "pvfs.auth.refused".into();
    let av = render(&auth, Privacy::Full, None);
    let a: serde_json::Value = serde_json::from_str(&format::ecs(&auth, &av)).unwrap();
    assert_eq!(a["event"]["category"][0], "authentication");
    // Found live (D222e): a refused cross-origin websocket is `web`, not `host`.
    let mut web = refusal();
    web.event = "pvos.web.origin_refused".into();
    let wv = render(&web, Privacy::Full, None);
    let w: serde_json::Value = serde_json::from_str(&format::ecs(&web, &wv)).unwrap();
    assert_eq!(w["event"]["category"][0], "web");
    assert_eq!(w["event"]["type"][0], "denied");
    let bulk = format::es_bulk(&[(&r, v)], "pvfs-logs", false);
    let lines: Vec<&str> = bulk.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "{\"create\":{\"_index\":\"pvfs-logs\"}}");
    assert!(serde_json::from_str::<serde_json::Value>(lines[1]).is_ok());
}

#[test]
fn ocsf_classes() {
    let r = refusal();
    let v = render(&r, Privacy::Full, None);
    let o: serde_json::Value = serde_json::from_str(&format::ocsf(&r, &v, "PVFS", "1.4")).unwrap();
    assert_eq!(o["class_uid"], 3002);
    assert_eq!(o["type_uid"], 300201);
    assert_eq!(o["status_id"], 2);
    assert_eq!(o["severity_id"], 3);
    assert_eq!(o["src_endpoint"]["ip"], "10.0.0.9");
    assert_eq!(o["actor"]["user"]["uid"], "key:02ab");
    assert_eq!(o["metadata"]["product"]["vendor_name"], "PhraseVault");
    assert_eq!(o["unmapped"]["op"], "ls");
    let mut change = rec("pvfs.authority.acl_set", "pvfsd: ACL set", Category::Audit, vec![]);
    change.outcome = Some(Outcome::Success);
    let cv = render(&change, Privacy::Full, None);
    let c: serde_json::Value = serde_json::from_str(&format::ocsf(&change, &cv, "PVFS", "1.4")).unwrap();
    assert_eq!(c["class_uid"], 3005);
    assert_eq!(c["status_id"], 1);
    let plain = rec("pvfs.job.failed", "pvfsd: x", Category::System, vec![]);
    let pv = render(&plain, Privacy::Full, None);
    let p: serde_json::Value = serde_json::from_str(&format::ocsf(&plain, &pv, "PVFS", "1.4")).unwrap();
    assert_eq!(p["class_uid"], 0);
    assert_eq!(p["type_uid"], 99);
}

#[test]
fn otlp_body() {
    let r = refusal();
    let v = render(&r, Privacy::Full, None);
    let b: serde_json::Value = serde_json::from_str(&format::otlp_body(&[(&r, v)])).unwrap();
    let lr = &b["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
    assert_eq!(lr["timeUnixNano"], "1791418934370000000");
    assert_eq!(lr["severityNumber"], 13);
    assert_eq!(lr["severityText"], "WARN");
    let attrs = lr["attributes"].as_array().unwrap();
    assert!(attrs.iter().any(|a| a["key"] == "pvfs.event" && a["value"]["stringValue"] == "pvfs.access.denied"));
    let res = b["resourceLogs"][0]["resource"]["attributes"].as_array().unwrap();
    assert!(res.iter().any(|a| a["key"] == "service.name" && a["value"]["stringValue"] == "pvfsd"));
}

#[test]
fn the_new_formats_keep_minimal_private() {
    let r = rec(
        "pvfs.mount.deleted",
        "mount: delete of Films/Obsession (2026)/x.mkv by chris@example.com",
        Category::System,
        vec![content("Films/Obsession (2026)/x.mkv").to_field("path"), identity("chris@example.com").to_field("email")],
    );
    let v = render(&r, Privacy::Minimal, Some(&[3u8; 32]));
    for out in [
        format::leef(&r, &v, "PVFS", "1"),
        format::rfc3164(&r, &v.line()),
        format::gelf(&r, &v),
        format::ecs(&r, &v),
        format::ocsf(&r, &v, "PVFS", "1"),
        format::otlp_body(&[(&r, v.clone())]),
    ] {
        assert!(!out.contains("Obsession") && !out.contains("chris@"), "{out}");
    }
}

#[test]
fn gelf_over_udp_and_tcp_and_es_and_otlp_over_http() {
    let r = refusal();
    let d = tempfile::tempdir().unwrap();
    // GELF over UDP.
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut g = dest(Kind::Gelf);
    g.address = Some(u.local_addr().unwrap().to_string());
    let gd = mk_dest(g, None, &d.path().join("g"));
    sender::deliver(&gd, std::slice::from_ref(&r)).unwrap();
    let mut buf = [0u8; 9000];
    let (n, _) = u.recv_from(&mut buf).unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();
    assert_eq!(doc["_event"], "pvfs.access.denied");
    // GELF over TCP: NUL-delimited.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut gt = dest(Kind::Gelf);
    gt.transport = Some("tcp".into());
    gt.address = Some(l.local_addr().unwrap().to_string());
    let t = std::thread::spawn(move || {
        let mut all = Vec::new();
        l.accept().unwrap().0.read_to_end(&mut all).unwrap();
        all
    });
    let gtd = mk_dest(gt, None, &d.path().join("gt"));
    sender::deliver(&gtd, &[r.clone(), r.clone()]).unwrap();
    let all = t.join().unwrap();
    assert_eq!(all.iter().filter(|b| **b == 0).count(), 2);
    // Elasticsearch: errors:true is a failure, ApiKey auth, x-ndjson.
    let (url, t) = http_server(vec![(200, "{\"took\":1,\"errors\":false,\"items\":[]}"), (200, "{\"took\":1,\"errors\":true,\"items\":[]}")]);
    let mut es = dest(Kind::Elasticsearch);
    es.url = Some(url);
    let esd = mk_dest(es, Some("k3y"), &d.path().join("es"));
    sender::deliver(&esd, std::slice::from_ref(&r)).unwrap();
    assert!(sender::deliver(&esd, std::slice::from_ref(&r)).is_err());
    let got = t.join().unwrap();
    assert!(got[0].0.starts_with("POST /_bulk HTTP/1.1"), "{}", got[0].0);
    assert!(got[0].0.contains("Content-Type: application/x-ndjson"));
    assert!(got[0].0.contains("Authorization: ApiKey k3y"));
    assert!(got[0].1.starts_with("{\"create\":{\"_index\":\"logs-pvfs-default\"}}\n"), "the default index");
    // OTLP: /v1/logs, a parsable body; https_json as ECS.
    let (url, t) = http_server(vec![(200, "{}"), (200, "ok")]);
    let mut o = dest(Kind::Otlp);
    o.url = Some(url.clone());
    let od = mk_dest(o, None, &d.path().join("o"));
    sender::deliver(&od, std::slice::from_ref(&r)).unwrap();
    let mut h = dest(Kind::HttpsJson);
    h.url = Some(url);
    h.format = Some("ecs".into());
    let hd = mk_dest(h, None, &d.path().join("h"));
    sender::deliver(&hd, std::slice::from_ref(&r)).unwrap();
    let got = t.join().unwrap();
    assert!(got[0].0.starts_with("POST /v1/logs HTTP/1.1"));
    assert!(serde_json::from_str::<serde_json::Value>(&got[0].1).unwrap()["resourceLogs"].is_array());
    let ecs: serde_json::Value = serde_json::from_str(got[1].1.trim()).unwrap();
    assert_eq!(ecs["event"]["action"], "pvfs.access.denied");
}

#[test]
fn the_new_kinds_validate() {
    let mut g = dest(Kind::Gelf);
    assert!(g.problems().iter().any(|p| p.contains("address")));
    g.address = Some("graylog:12201".into());
    assert!(g.problems().is_empty());
    g.transport = Some("http".into());
    assert!(g.problems().iter().any(|p| p.contains("url")));
    let mut h = dest(Kind::HttpsJson);
    h.url = Some("https://x".into());
    h.format = Some("xml".into());
    assert!(h.problems().iter().any(|p| p.contains("format")));
    let mut s = dest(Kind::Syslog);
    s.address = Some("siem:514".into());
    s.format = Some("leef".into());
    assert!(s.problems().is_empty());
    assert_eq!(Kind::parse("graylog"), Some(Kind::Gelf));
    assert_eq!(Kind::parse("opensearch"), Some(Kind::Elasticsearch));
    assert_eq!(Kind::parse("otel"), Some(Kind::Otlp));
}

/// PVOS D226 — the shared questions, answered by a script.
fn scripted<'a>(answers: &'a [&'a str]) -> impl FnMut(&str, Option<&str>) -> Result<String, String> + 'a {
    let mut i = 0;
    move |_q, default| {
        let a = answers.get(i).copied().ok_or("ran out of answers")?;
        i += 1;
        Ok(if a.is_empty() { default.unwrap_or("").to_string() } else { a.to_string() })
    }
}

#[test]
fn ask_destination_builds_what_the_cli_built() {
    // Loki, all defaults but a label; minimal privacy needs no confirm.
    let mut ask = scripted(&["", "", "", "env=prod", "", "", "", ""]);
    let a = ask_destination(&[], &mut ask, &mut |_| Ok(false)).unwrap();
    let d = &a.destination;
    assert_eq!((d.name.as_str(), d.kind, d.url.as_deref()), ("logs", Kind::Loki, Some("http://192.168.1.83:3100")));
    assert_eq!(d.labels.get("env").map(String::as_str), Some("prod"));
    assert_eq!((d.privacy.as_str(), d.min_severity.as_str()), ("minimal", "info"));
    assert!(d.categories.is_empty() && a.token.is_empty());
    assert!(d.problems().is_empty(), "{:?}", d.problems());
    // Elasticsearch over https with a pin, security only; "logs" is taken so a name is asked.
    let mut ask = scripted(&["es", "elasticsearch", "https://es.example:9200", "", "yes", "k3y ", "pin", "AB:CD", "", "warning", "security"]);
    let a = ask_destination(&["logs".to_string()], &mut ask, &mut |_| Ok(false)).unwrap();
    let d = &a.destination;
    assert_eq!((d.kind, d.index.as_deref()), (Kind::Elasticsearch, Some("logs-pvfs-default")));
    assert_eq!(d.tls.pin_sha256.as_deref(), Some("AB:CD"));
    assert!(d.doc_ids, "PVOS D228: asked, and answered yes");
    assert_eq!(a.token, "k3y", "trimmed");
    assert_eq!(d.categories, vec!["security".to_string()]);
    assert_eq!(d.min_severity, "warning");
    // A wrong type is asked again; `full` privacy needs a yes, and a no stops it.
    let mut ask = scripted(&["s", "carrier-pigeon", "syslog", "udp", "siem:514", "cef", "full"]);
    let e = ask_destination(&[], &mut ask, &mut |q| { assert!(q.contains("everything")); Ok(false) }).err().unwrap();
    assert_eq!(e, "not added");
    // A taken name is refused at once.
    let mut ask = scripted(&["logs"]);
    assert!(ask_destination(&["logs".to_string()], &mut ask, &mut |_| Ok(true)).err().unwrap().contains("already"));
}

/// PVOS D228 — `doc_ids`: the record's id is the document's `_id`, and a
/// reply whose failed items are all 409 (already there) is a delivery; any
/// other item error fails the batch. Without it, no `_id`.
#[test]
fn elasticsearch_doc_ids_make_a_resend_a_delivery() {
    let d = tempfile::tempdir().unwrap();
    let r = rec("pvfs.auth.refused", "pvfsd: refused", Category::Security, vec![]);
    let v = render(&r, Privacy::Full, None);
    let with = format::es_bulk(&[(&r, v.clone())], "logs-pvfs-default", true);
    assert!(with.lines().next().unwrap().contains(&format!("\"_id\":\"{}\"", r.id)), "{with}");
    assert!(!format::es_bulk(&[(&r, v)], "logs-pvfs-default", false).contains("_id"));
    let dup = r#"{"took":1,"errors":true,"items":[{"create":{"status":409,"error":{"type":"version_conflict_engine_exception"}}},{"create":{"status":201}}]}"#;
    let bad = r#"{"took":1,"errors":true,"items":[{"create":{"status":409}},{"create":{"status":400,"error":{"type":"mapper_parsing_exception"}}}]}"#;
    let (url, t) = http_server(vec![(200, dup), (200, bad), (200, dup)]);
    let mut es = dest(Kind::Elasticsearch);
    es.url = Some(url);
    es.doc_ids = true;
    let ed = mk_dest(es.clone(), Some("k3y"), &d.path().join("es"));
    sender::deliver(&ed, std::slice::from_ref(&r)).expect("409s are already-delivered records");
    assert!(sender::deliver(&ed, std::slice::from_ref(&r)).unwrap_err().contains("400"), "a 400 item fails the batch");
    // Without doc_ids, the same 409 reply is a failure (it cannot be ours).
    let mut plain = es;
    plain.doc_ids = false;
    let pd = mk_dest(plain, Some("k3y"), &d.path().join("es2"));
    assert!(sender::deliver(&pd, std::slice::from_ref(&r)).is_err());
    let got = t.join().unwrap();
    assert!(got[0].1.contains("\"_id\""), "{}", got[0].1);
    assert!(!got[2].1.contains("\"_id\""), "{}", got[2].1);
    // doc_ids on another type is a config problem.
    let mut l = dest(Kind::Loki);
    l.url = Some("http://loki:3100".into());
    l.doc_ids = true;
    assert!(l.problems().iter().any(|p| p.contains("doc_ids")), "{:?}", l.problems());
}

