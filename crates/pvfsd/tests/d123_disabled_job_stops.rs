//! D123 — a disabled periodic job STOPS, and the row says `disabled` from
//! then on. Its own test binary: it sets process-wide environment (the
//! config dir for the instance registry, a 1s idle timeout) that the other
//! serve-jobs tests must not see.

use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pvfs_client::Client;
use pvfs_core::{crypto, identity, serve as serve_cfg, Engine};
use pvfsd::jobs::JobsState;
use pvfsd::{serve, Daemon};

/// D123 — a disabled periodic job STOPS, and the row says `disabled` from
/// then on: never `idle`, never a stale error. The pass is made slow by a
/// holder that accepts the connection and never speaks (each file costs one
/// idle timeout), so the runner's disable has something to interrupt.
#[test]
fn a_disabled_periodic_job_stops_and_reads_disabled() {
    use pvfs_core::{BindSpec, HashPolicy, NodeSpec, TYPE_FOLDER};
    use std::net::TcpListener;

    // A holder that answers the dial and then says nothing.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });
    let pin = "7".repeat(64);
    let cfg = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(cfg.path().join("pvfs")).unwrap();
    std::fs::write(cfg.path().join("pvfs/instances"), format!("silent {addr} {pin}\n")).unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    // Each dial to the silent holder costs one idle timeout; make that a
    // second, so an UNCUT pass over twelve files would take twelve seconds
    // and a cut one ends within a couple.
    std::env::set_var("PVFS_IDLE_TIMEOUT_SECS", "1");

    // A library of twelve files whose bytes are gone locally and whose only
    // other copy is at the silent holder.
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("local");
    std::fs::create_dir_all(&src).unwrap();
    for n in 0..12u8 {
        std::fs::write(src.join(format!("f{n:02}.mkv")), vec![b'a' + n; 4096]).unwrap();
    }
    let (mut engine, owner_mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Media".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine
        .bind_folder(
            &media,
            BindSpec {
                source_uri: format!("file://{}", src.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
    engine.scan_routed(Some(&media), None, 0).unwrap();
    for c in engine.children(&media).unwrap() {
        engine
            .add_location(&c.node.id, &format!("pvfs-host://{pin}/lib/{}", c.label))
            .unwrap();
        std::fs::remove_file(src.join(&c.label)).unwrap();
    }
    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_placement(&data_dir, &media, true).unwrap();
    serve_cfg::set_job(&data_dir, "sync", true).unwrap();
    let mkey = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let mpub = crypto::pubkey_bytes(&mkey);
    engine.authorize_member(&owner_mn, &mpub).unwrap();

    let daemon = Arc::new(Daemon::new(engine));
    let jobs = Arc::new(JobsState::load(data_dir.clone()).unwrap());
    daemon.attach_jobs(Arc::clone(&jobs));
    let shutdown: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let reload: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let runner = {
        let j = Arc::clone(&jobs);
        std::thread::spawn(move || pvfsd::jobs::run(j, shutdown, reload, None))
    };
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let mut client = Client::connect_signed(&sock, &mpub, |d| {
        crypto::sign_digest(&mkey, d).unwrap()
    })
    .unwrap();
    let state_of = |client: &mut Client, name: &str| -> (String, Option<String>) {
        let (_, rows) = client.serve_status().unwrap();
        let r = rows.iter().find(|r| r.name == name).unwrap();
        (r.state.clone(), r.last_error.clone())
    };

    // The pass starts and sits on the silent holder.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while state_of(&mut client, "sync").0 != "running" {
        assert!(std::time::Instant::now() < deadline, "the sync pass never started");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Disable it mid-pass.
    let t0 = std::time::Instant::now();
    serve_cfg::set_job(&data_dir, "sync", false).unwrap();
    reload.store(true, Ordering::SeqCst);
    let deadline = t0 + std::time::Duration::from_secs(3);
    loop {
        let (s, _) = state_of(&mut client, "sync");
        assert_ne!(s, "idle", "a disabled job must never read idle");
        if s == "disabled" {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "row never read disabled (last: {s})");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // The pass ends at the next file boundary (one idle timeout away at
    // most), and shutdown then has nothing to wait for. Twelve uncut files
    // would take twelve seconds; a cut pass is joined well inside six.
    shutdown.store(true, Ordering::SeqCst);
    let joined = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = runner.join();
        let _ = joined.0.send(());
    });
    assert!(
        joined.1.recv_timeout(std::time::Duration::from_secs(6)).is_ok(),
        "the stopped pass must have exited; shutdown waited on it ({:?} since disable)",
        t0.elapsed()
    );
    let (s, err) = state_of(&mut client, "sync");
    assert_eq!(s, "disabled", "the finishing pass must not resurrect the row");
    assert_eq!(err, None, "a disabled job has no current error");
}
