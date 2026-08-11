//! P5.0/P5.1 — the serve-job supervisor (doc 18 §2/§5): config rows over the
//! socket, the reload path the SIGHUP handler drives, and the `follow` job
//! keeping a replica fresh with no CLI process.

use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pvfs_client::Client;
use pvfs_core::acl::{self, Principal};
use pvfs_core::log_store::EventRow;
use pvfs_core::{crypto, identity, serve as serve_cfg, Engine, ReplicaSource, ReplicaStore};
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

/// P5.1's "done means": events authored on the owner appear on a replica via
/// the daemon's `follow` job — no CLI follower process anywhere.
#[test]
fn follow_job_keeps_a_replica_fresh() {
    // the job dials with the box's client identity — point it at a private
    // config dir and authorize that identity on the owner's forest
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let client_mn = identity::client_identity_mnemonic().unwrap();
    let client_key = identity::device_key(&client_mn, "", 0).unwrap();
    let client_pub = crypto::pubkey_bytes(&client_key);

    // ---- the owner forest, served on a unix socket
    let odir = tempfile::tempdir().unwrap();
    let (mut owner, owner_mn) = Engine::init(odir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    owner.authorize_member(&owner_mn, &client_pub).unwrap();
    // rwa: replication needs root admin; the test also writes as this key
    owner
        .set_acl(&root, &Principal::Key(client_pub.clone()), acl::ACL_RWA)
        .unwrap();
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("owner.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(owner));
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }

    // ---- build the replica over the wire, record its source
    let mut client = Client::connect_signed(&sock, &client_pub, |d| {
        crypto::sign_digest(&client_key, d).unwrap()
    })
    .unwrap();
    let rdir = tempfile::tempdir().unwrap();
    let rdata = rdir.path().join(".pvfs");
    {
        let mut store = ReplicaStore::open(&rdata).unwrap();
        let mut from = 1;
        loop {
            let (_tip, events) = client.log_read(from, 64).unwrap();
            if events.is_empty() {
                break;
            }
            let rows: Vec<EventRow> = events
                .iter()
                .map(|w| EventRow {
                    seq: w.seq,
                    kind: w.kind.clone(),
                    body: hex::decode(&w.body).unwrap(),
                    chain_hash: hex::decode(&w.chain_hash).unwrap(),
                    written_at: w.written_at,
                })
                .collect();
            from = store.append(&rows).unwrap() + 1;
        }
    }
    ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
    }
    .save(&rdata)
    .unwrap();

    // ---- enable follow, start the supervisor (what the pvfsd binary runs)
    serve_cfg::set_job(&rdata, "follow", true).unwrap();
    let jobs = Arc::new(JobsState::load(rdata.clone()).unwrap());
    let shutdown: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let reload: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let runner = {
        let j = Arc::clone(&jobs);
        std::thread::spawn(move || pvfsd::jobs::run(j, shutdown, reload))
    };

    // ---- author on the owner; the follower must fold it within seconds
    client
        .mkdir(&root, "hot-news", |d| {
            crypto::sign_digest(&client_key, d).unwrap()
        })
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let seen = Engine::open(&rdata)
            .map(|replica| {
                let labels: Vec<String> = replica
                    .children(&root)
                    .unwrap_or_default()
                    .iter()
                    .map(|c| c.node.label.clone())
                    .collect();
                let _ = replica.close();
                labels.contains(&"hot-news".to_string())
            })
            .unwrap_or(false);
        if seen {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "follow job never folded the owner's event; rows: {:?}",
            jobs.snapshot()
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // the status row reflects a working follower (the fold lands just before
    // the CaughtUp callback stamps the row — give it a beat)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let row = jobs
            .snapshot()
            .into_iter()
            .find(|r| r.name == "follow")
            .unwrap();
        if row.state == "running" && row.last_ok_ms.is_some() && row.last_error.is_none() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "follow row never settled: {row:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    shutdown.store(true, Ordering::SeqCst);
    runner.join().unwrap();
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
