//! P5.0 — the serve-job skeleton (doc 18 §2): config rows over the socket,
//! runner attach/absent, and the reload path the SIGHUP handler drives.

use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pvfs_client::Client;
use pvfs_core::{serve as serve_cfg, Engine};
use pvfsd::jobs::JobsState;
use pvfsd::{serve, Daemon};

#[test]
fn serve_status_reports_config_runner_and_reload() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let data_dir = engine.data_dir().to_path_buf();
    serve_cfg::set_job(&data_dir, "sync", true).unwrap();

    let daemon = Arc::new(Daemon::new(engine));
    let jobs = Arc::new(JobsState::load(data_dir.clone()).unwrap());
    daemon.attach_jobs(Arc::clone(&jobs));

    // the runner loop, driven by the same flags the binary's signal handlers set
    let shutdown: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let reload: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let runner = {
        let j = Arc::clone(&jobs);
        std::thread::spawn(move || pvfsd::jobs::run(j, shutdown, reload))
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

    // ---- status over the socket: every known job, config reflected
    let mut client = Client::connect_public(&sock).unwrap();
    let (runner_state, rows) = client.serve_status().unwrap();
    assert_eq!(runner_state, "on");
    assert_eq!(rows.len(), serve_cfg::JOB_NAMES.len());
    let row = |name: &str| rows.iter().find(|r| r.name == name).unwrap().clone();
    assert!(row("sync").enabled);
    assert_eq!(row("sync").state, "idle");
    assert!(!row("follow").enabled);
    assert_eq!(row("follow").state, "disabled");

    // ---- reload: edit the config, flip the flag the SIGHUP handler sets
    serve_cfg::set_job(&data_dir, "export", true).unwrap();
    reload.store(true, Ordering::SeqCst);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let (_, rows) = client.serve_status().unwrap();
        if rows.iter().any(|r| r.name == "export" && r.enabled) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "runner never picked up the reload"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    shutdown.store(true, Ordering::SeqCst);
    runner.join().unwrap();
}

#[test]
fn daemon_without_runner_reports_off() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let daemon = Arc::new(Daemon::new(engine));

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });

    let mut client = Client::connect_public(&sock).unwrap();
    let (runner_state, rows) = client.serve_status().unwrap();
    assert_eq!(runner_state, "off");
    assert!(rows.is_empty());
}

#[test]
fn corrupt_jobs_file_refuses_load_but_reload_keeps_config() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let data_dir = engine.data_dir().to_path_buf();
    drop(engine);

    // a corrupt file refuses the initial load (the daemon would not start)
    std::fs::write(serve_cfg::jobs_path(&data_dir), "not-a-jobs-file\n").unwrap();
    assert!(JobsState::load(data_dir.clone()).is_err());

    // a good config that later goes corrupt: reload fails, rows survive
    std::fs::remove_file(serve_cfg::jobs_path(&data_dir)).unwrap();
    serve_cfg::set_job(&data_dir, "evict", true).unwrap();
    let jobs = JobsState::load(data_dir.clone()).unwrap();
    std::fs::write(serve_cfg::jobs_path(&data_dir), "corrupted mid-edit\n").unwrap();
    assert!(jobs.reload().is_err());
    assert!(jobs
        .snapshot()
        .iter()
        .any(|r| r.name == "evict" && r.enabled));
}
