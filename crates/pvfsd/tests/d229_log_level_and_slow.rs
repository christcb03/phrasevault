//! PVOS D229 — the box's log level, changed live (`SetLogLevel`, proto 17):
//! a member over the box's own socket may, a member over the network may
//! not, the forest root's admin may from anywhere; `serve status` shows it.
//! And a slow request is a record: `pvfs.request.slow`, never for the long
//! poll. One test: the level and the slow threshold are process-wide.

use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pvfs_client::Client;
use pvfs_core::{crypto, identity, Engine};
use pvfs_log::testing::GlobalCapture;
use pvfs_log::{Record, Severity};
use pvfsd::{nettls, serve, serve_tls_until, Daemon};

fn field(r: &Record, name: &str) -> String {
    r.fields.iter().find(|f| f.name == name).map(|f| f.value.to_string()).unwrap_or_default()
}

fn wait_for(cap: &GlobalCapture, event: &str, pick: impl Fn(&Record) -> bool) -> Vec<Record> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let got: Vec<Record> = cap.events(event).into_iter().filter(|r| pick(r)).collect();
        if !got.is_empty() || Instant::now() > deadline {
            return got;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_log_level_changes_live_under_its_gate_and_slow_requests_are_logged() {
    // Every request is "slow" at 0 ms: what is logged, and what never is.
    // Set before any thread starts, and before the threshold is first read.
    std::env::set_var("PVFS_SLOW_REQUEST_MS", "0");
    let cap = GlobalCapture::start();

    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let owner_key = identity::device_key(&owner_mn, "", 0).unwrap();
    let owner_pub = crypto::pubkey_bytes(&owner_key);
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();
    let data_dir = engine.data_dir().to_path_buf();

    let daemon = Arc::new(Daemon::new(engine));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let ul = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(ul, d);
        });
    }
    let tls = nettls::load_or_generate(dir.path()).unwrap();
    let tl = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tl.local_addr().unwrap().to_string();
    {
        let d = Arc::clone(&daemon);
        let cfg = Arc::clone(&tls.config);
        std::thread::spawn(move || {
            static NEVER: AtomicBool = AtomicBool::new(false);
            let _ = serve_tls_until(tl, cfg, d, &NEVER);
        });
    }

    // ---- 1. a member on the box's own socket: debug for 2 minutes
    let mut local = Client::connect_signed(&sock, &member_pub, |d| crypto::sign_digest(&member_key, d).unwrap()).unwrap();
    let before = local.serve_status_full().unwrap().log_level.expect("a D229 daemon reports its level");
    assert_eq!((before.configured.as_str(), before.current.as_str(), before.until_ms), ("info", "info", 0));
    let set = local.set_log_level("debug", 2).unwrap();
    assert_eq!(set.current, "debug");
    assert_eq!(set.configured, "info");
    assert_eq!(set.by, format!("key:{}", hex::encode(&member_pub)));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    assert!(set.until_ms > now + 60_000 && set.until_ms <= now + 120_000, "{set:?}");
    assert_eq!(pvfs_log::current_level(), Severity::Debug, "applied in this process at once");
    let file = pvfs_log::level::read(&data_dir).unwrap().expect("the file every process of the box reads");
    assert_eq!((file.level.as_str(), file.until_ms), ("debug", set.until_ms));
    let changed = wait_for(&cap, "pvfs.log.level_changed", |r| field(r, "level") == "debug");
    assert_eq!(changed.len(), 1, "said once: {changed:?}");
    assert_eq!(field(&changed[0], "by"), set.by);
    let status = local.serve_status_full().unwrap().log_level.unwrap();
    assert_eq!((status.current.as_str(), status.until_ms), ("debug", set.until_ms));

    // ---- 2. a bad level, and too long a time
    let e = local.set_log_level("loud", 5).unwrap_err().to_string();
    assert!(e.starts_with("bad_input") && e.contains("debug"), "{e}");
    let e = local.set_log_level("debug", 2_000).unwrap_err().to_string();
    assert!(e.starts_with("bad_input") && e.contains("at most a day"), "{e}");

    // ---- 3. the same member over the network: refused
    let mut remote_member = Client::connect_tcp_signed(&addr, &tls.pin, &member_pub, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();
    let e = remote_member.set_log_level("debug", 5).unwrap_err().to_string();
    assert!(e.starts_with("forbidden") && e.contains("admin rights on the forest root"), "{e}");
    assert_eq!(pvfs_log::level::read(&data_dir).unwrap().unwrap().until_ms, set.until_ms, "unchanged");

    // ---- 4. the root's admin over the network: back to the configured level
    let mut owner = Client::connect_tcp_signed(&addr, &tls.pin, &owner_pub, |d| crypto::sign_digest(&owner_key, d).unwrap())
        .unwrap();
    let back = owner.set_log_level("default", 0).unwrap();
    assert_eq!((back.current.as_str(), back.until_ms), ("info", 0));
    assert_eq!(pvfs_log::current_level(), Severity::Info);
    assert!(pvfs_log::level::read(&data_dir).unwrap().is_none(), "the file is gone");
    let cleared = wait_for(&cap, "pvfs.log.level_changed", |r| field(r, "reason") == "cleared");
    assert_eq!(cleared.len(), 1, "{cleared:?}");

    // ---- 5. slow requests: each op answered is logged at 0 ms, with who
    // asked; the long poll is not; and this test's clients (not a daemon)
    // log nothing of their own waits.
    let slow = wait_for(&cap, "pvfs.request.slow", |r| field(r, "op") == "set_log_level" && field(r, "peer_addr") == "local");
    assert!(!slow.is_empty(), "{:?}", cap.events("pvfs.request.slow"));
    assert_eq!(field(&slow[0], "error_kind"), "slow:request");
    assert!(slow[0].line().starts_with("pvfsd: set_log_level from local took "), "{}", slow[0].line());
    let tcp = wait_for(&cap, "pvfs.request.slow", |r| field(r, "op") == "set_log_level" && field(r, "peer_addr").starts_with("127.0.0.1:"));
    assert!(!tcp.is_empty());
    let tip = owner.log_info("").unwrap_or(0);
    let _ = owner.log_wait(tip + 1_000, 10, 300, "");
    std::thread::sleep(Duration::from_millis(300));
    assert!(cap.events("pvfs.request.slow").iter().all(|r| field(r, "op") != "log_wait"), "the long poll is never slow");
    assert!(cap.events("pvfs.client.request_slow").is_empty(), "a CLI or test client is not a daemon");
    assert!(pvfs_client::client_wait_is_slow(true, "serve_status", Duration::from_secs(6), Duration::from_secs(5)));
    assert!(!pvfs_client::client_wait_is_slow(true, "log_wait", Duration::from_secs(60), Duration::from_secs(5)));
    assert!(!pvfs_client::client_wait_is_slow(false, "serve_status", Duration::from_secs(60), Duration::from_secs(5)));
    assert!(!pvfs_client::client_wait_is_slow(true, "serve_status", Duration::from_secs(4), Duration::from_secs(5)));
}
