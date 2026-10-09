//! PVOS D230 — `Diagnose`: a member gets the box's config, clock and its
//! failures since a time from the problems file (the newest 300 at most); a
//! key that is not a member is refused. One test: the problems file is
//! process-wide.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::Client;
use pvfs_core::{crypto, identity, Engine};
use pvfs_log::pv_warn;
use pvfsd::{serve, Daemon, DIAGNOSE_MAX_PROBLEMS};

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

#[test]
fn diagnose_says_what_the_box_is_and_its_recent_failures() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();
    let stranger_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let stranger_pub = crypto::pubkey_bytes(&stranger_key);
    let forest = engine.identity.forest_id.clone();
    let data_dir = engine.data_dir().to_path_buf();
    let daemon = Arc::new(Daemon::new(engine));
    daemon.set_listen("127.0.0.1:7434".into());
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let l = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(l, d);
        });
    }

    // Before a problems file is named (an embedded daemon): it says so.
    let mut member = Client::connect_signed(&sock, &member_pub, |d| crypto::sign_digest(&member_key, d).unwrap()).unwrap();
    let d = member.diagnose(0).unwrap();
    assert!(d.problems.is_empty() && d.problems_note.contains("no problems file"), "{d:?}");

    pvfs_log::problems::open(data_dir.join(pvfs_log::problems::FILE_NAME));
    let t0 = now();
    for i in 0..(DIAGNOSE_MAX_PROBLEMS + 5) {
        pv_warn!("pvfs.test.d230", n = i, error_kind = "disk:no_space"; "pvfsd: d230 failure {i}");
    }
    let before_call = now();
    let d = member.diagnose(t0).unwrap();
    let after_call = now();
    assert_eq!(d.forest, forest);
    assert_eq!(d.role, "owner");
    assert_eq!(d.listen, "127.0.0.1:7434");
    assert_eq!(d.jobs, "none");
    assert_eq!(d.regions, "none");
    assert_eq!(d.privacy, "full");
    assert!(!d.build.is_empty() && !d.host.is_empty());
    assert!(d.now_ms >= before_call && d.now_ms <= after_call, "the box's clock at the answer");
    assert!(d.started_ms <= t0);
    assert_eq!(d.problems.len(), DIAGNOSE_MAX_PROBLEMS);
    assert_eq!(d.problems_left_out, 5);
    let first = &d.problems[0];
    assert_eq!(first.line, "pvfsd: d230 failure 5", "the newest 300 are kept");
    assert_eq!((first.severity.as_str(), first.event.as_str(), first.error_kind.as_str()), ("warning", "pvfs.test.d230", "disk:no_space"));
    assert_eq!(d.problems.last().unwrap().line, format!("pvfsd: d230 failure {}", DIAGNOSE_MAX_PROBLEMS + 4));
    // Since later than all of them: none.
    assert!(member.diagnose(now() + 60_000).unwrap().problems.is_empty());

    // A key that is not a member is refused.
    let mut stranger = Client::connect_signed(&sock, &stranger_pub, |d| crypto::sign_digest(&stranger_key, d).unwrap()).unwrap();
    let e = stranger.diagnose(0).unwrap_err().to_string();
    assert!(e.starts_with("forbidden") && e.contains("member-gated"), "{e}");
}
