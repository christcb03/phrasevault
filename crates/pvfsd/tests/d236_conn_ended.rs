//! PVOS D236 — say why a connection ended. The daemon logs one
//! `pvfs.conn.ended` line per connection, at debug (expected behavior), with
//! the reason, the peer, its age, the requests served and the last op; the
//! client says which connection a request lost. On 2026-10-10 the owner
//! logged nothing when two routed-write connections closed, and nobody could
//! say why.

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pvfs_client::{Client, ClientError};
use pvfs_core::Engine;
use pvfs_log::testing::GlobalCapture;
use pvfs_log::{Record, Severity, Value};
use pvfs_proto::{read_msg, write_msg, ClientMsg, ServerMsg};
use pvfsd::{serve, Daemon};

fn field<'a>(r: &'a Record, name: &str) -> Option<&'a Value> {
    r.fields.iter().find(|f| f.name == name).map(|f| &f.value)
}

fn s(v: Option<&Value>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

/// Wait up to 5 s for a `pvfs.conn.ended` record that `pick` accepts.
fn ended(cap: &GlobalCapture, pick: impl Fn(&Record) -> bool) -> Option<Record> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(r) = cap.events("pvfs.conn.ended").into_iter().find(|r| pick(r)) {
            return Some(r);
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_daemon_says_why_each_connection_ended_at_debug() {
    let cap = GlobalCapture::start();
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(engine));
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }

    // ---- a client that signs in, asks twice and hangs up
    let mut c = Client::connect_public(&sock).unwrap();
    c.info().unwrap();
    c.info().unwrap();
    drop(c);
    let r = ended(&cap, |r| s(field(r, "reason")) == "peer_closed").expect("a line for the connection that hung up");
    assert_eq!(r.severity, Severity::Debug, "expected behavior is debug: {r:?}");
    assert_eq!(s(field(&r, "requests")), "2", "{r:?}");
    assert_eq!(s(field(&r, "op")), "info", "{r:?}");
    assert_eq!(s(field(&r, "peer_addr")), "local", "{r:?}");
    assert!(r.line().contains("ended — peer_closed"), "{}", r.line());

    // ---- a connection that hangs up before it signs in
    {
        let mut raw = UnixStream::connect(&sock).unwrap();
        let _: Option<ServerMsg> = read_msg(&mut raw).unwrap(); // the challenge, unanswered
    }
    let r = ended(&cap, |r| s(field(r, "reason")) == "before_ready").expect("a line for the connection that never signed in");
    assert_eq!(r.severity, Severity::Debug);
    assert_eq!(s(field(&r, "requests")), "0", "{r:?}");
}

#[test]
fn a_lost_request_says_which_connection_it_lost() {
    // A peer that signs the client in, reads one request and hangs up.
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("fake.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        write_msg(
            &mut s,
            &ServerMsg::Challenge { nonce: "00".repeat(32), forest_id: "f".into(), expiry_ms: u64::MAX, version: pvfs_proto::PROTO_VERSION },
        )
        .unwrap();
        let _: Option<ClientMsg> = read_msg(&mut s).unwrap();
        write_msg(&mut s, &ServerMsg::Ready { principal: "public".into() }).unwrap();
        let _: Option<ClientMsg> = read_msg(&mut s).unwrap();
        // and hangs up without an answer
    });
    let mut c = Client::connect_public(&sock).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let e = c.info().expect_err("the peer hung up");
    let text = e.to_string();
    assert!(matches!(e, ClientError::Protocol(_)), "the type is kept (D200 reads it): {e:?}");
    assert!(text.contains("connection closed"), "{text}");
    assert!(text.contains("to the local daemon"), "the peer: {text}");
    assert!(text.contains("connected ") && text.contains(" s ago"), "the age: {text}");
    assert!(text.contains("idle 0.") && text.contains("before this info"), "the idle time and the op: {text}");
}
