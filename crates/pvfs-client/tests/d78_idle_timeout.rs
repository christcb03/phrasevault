//! D78 — a read that can never end.
//!
//! The root cause of two multi-hour stalls: PVFS set no socket read timeout, so
//! a request whose reply never came blocked the calling thread FOREVER. Caught
//! in the act on a lab box — a thread in `wait_woken`, the connection
//! ESTABLISHED, zero bytes queued either way, both peers idle. Nothing had
//! failed; it was waiting for something that was never coming.
//!
//! The serve job owning that thread reported `running`, with no error, for 6.4
//! hours on production.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// A peer that ACCEPTS and then says nothing — the exact shape that hung us.
/// Not a refused connection, not a dropped one: established and silent.
fn silent_peer() -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let h = std::thread::spawn(move || {
        // Accept, then hold the connection open and never write a byte.
        if let Ok((stream, _)) = listener.accept() {
            std::thread::sleep(Duration::from_secs(30));
            drop(stream);
        }
    });
    (addr, h)
}

/// The property, at the socket layer: with a timeout set, a silent peer costs
/// you the timeout. Without one it costs you forever.
#[test]
fn a_read_from_a_silent_peer_ends() {
    let (addr, _h) = silent_peer();
    let sock = TcpStream::connect(&addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(600)))
        .unwrap();

    let started = Instant::now();
    let mut buf = [0u8; 16];
    let r = (&sock).read(&mut buf);
    let waited = started.elapsed();

    assert!(r.is_err(), "a silent peer must produce an error, not a hang");
    assert!(
        waited < Duration::from_secs(5),
        "and it must end promptly — it took {waited:?}"
    );
    let kind = r.unwrap_err().kind();
    assert!(
        matches!(
            kind,
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "expected a timeout, got {kind:?}"
    );
}

/// And the control that makes the test meaningful: the SAME silent peer, with
/// no timeout set, does not return. If this assertion ever fails, the test
/// above is proving nothing.
#[test]
fn without_a_timeout_the_same_read_does_not_return() {
    let (addr, _h) = silent_peer();
    let sock = TcpStream::connect(&addr).unwrap();
    // deliberately NO set_read_timeout — the pre-D78 behaviour

    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = done.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 16];
        let _ = (&sock).read(&mut buf);
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    std::thread::sleep(Duration::from_secs(2));
    assert!(
        !done.load(std::sync::atomic::Ordering::SeqCst),
        "an untimed read from a silent peer must still be blocked — this is the \
         bug, and if it returns the test above proves nothing"
    );
}

/// The knob is real, and refuses to disable itself: 0 or nonsense falls back to
/// the default rather than restoring the unbounded wait.
#[test]
fn the_timeout_cannot_be_switched_off() {
    std::env::set_var("PVFS_IDLE_TIMEOUT_SECS", "5");
    assert_eq!(pvfs_client::idle_timeout(), Duration::from_secs(5));

    std::env::set_var("PVFS_IDLE_TIMEOUT_SECS", "0");
    assert_eq!(
        pvfs_client::idle_timeout(),
        Duration::from_secs(pvfs_client::IDLE_TIMEOUT_DEFAULT_SECS),
        "zero must NOT mean 'wait forever' — that is the bug"
    );

    std::env::set_var("PVFS_IDLE_TIMEOUT_SECS", "banana");
    assert_eq!(
        pvfs_client::idle_timeout(),
        Duration::from_secs(pvfs_client::IDLE_TIMEOUT_DEFAULT_SECS)
    );
    std::env::remove_var("PVFS_IDLE_TIMEOUT_SECS");
}
