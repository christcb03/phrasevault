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
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let data_dir = engine.data_dir().to_path_buf();
    serve_cfg::set_job(&data_dir, "sync", true).unwrap();
    // punch F: status is member-gated — authorize the test client
    let mkey = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let mpub = crypto::pubkey_bytes(&mkey);
    engine.authorize_member(&owner_mn, &mpub).unwrap();

    let daemon = Arc::new(Daemon::new(engine));
    let jobs = Arc::new(JobsState::load(data_dir.clone()).unwrap());
    daemon.attach_jobs(Arc::clone(&jobs));

    // the runner loop, driven by the same flags the binary's signal handlers set
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

    // ---- status over the socket (member-signed): every known job listed
    let mut client = Client::connect_signed(&sock, &mpub, |d| {
        crypto::sign_digest(&mkey, d).unwrap()
    })
    .unwrap();
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
fn daemon_without_runner_reports_off_and_gates_anon() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let mkey = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let mpub = crypto::pubkey_bytes(&mkey);
    engine.authorize_member(&owner_mn, &mpub).unwrap();
    let daemon = Arc::new(Daemon::new(engine));

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });

    // punch F: anonymous status is refused outright
    let mut anon = Client::connect_public(&sock).unwrap();
    assert!(matches!(
        anon.serve_status(),
        Err(pvfs_client::ClientError::Server { code, .. }) if code == "forbidden"
    ));
    // a member sees runner off (no runner attached in this test)
    let mut client = Client::connect_signed(&sock, &mpub, |d| {
        crypto::sign_digest(&mkey, d).unwrap()
    })
    .unwrap();
    let (runner_state, rows) = client.serve_status().unwrap();
    assert_eq!(runner_state, "off");
    assert!(rows.is_empty());
}

/// One process-wide config dir: tests run on threads, and the client
/// identity is resolved through env — two tests racing `XDG_CONFIG_HOME`
/// to different dirs would flake. Same dir → same identity, no race.
fn test_config_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let d = DIR.get_or_init(|| tempfile::tempdir().unwrap());
    std::env::set_var("XDG_CONFIG_HOME", d.path());
    d.path()
}

/// P5.1's "done means": events authored on the owner appear on a replica via
/// the daemon's `follow` job — no CLI follower process anywhere.
#[test]
fn follow_job_keeps_a_replica_fresh() {
    // the job dials with the box's client identity — authorize it on the owner
    test_config_dir();
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
            let (_tip, events) = client.log_read(from, 64, "").unwrap();
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
        region: String::new(),
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
        std::thread::spawn(move || pvfsd::jobs::run(j, shutdown, reload, None))
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

/// P5.2's "done means": content on the owner reaches a consumer's export
/// view hands-free — follow folds it, sync pulls the bytes, export
/// materializes it, all as daemon jobs.
#[test]
fn sync_and_export_jobs_keep_a_consumer_view_fresh() {
    use pvfs_core::FilePayload;

    test_config_dir();
    let client_mn = identity::client_identity_mnemonic().unwrap();
    let client_key = identity::device_key(&client_mn, "", 0).unwrap();
    let client_pub = crypto::pubkey_bytes(&client_key);

    // ---- owner: a folder with one real file, served on a unix socket
    let odir = tempfile::tempdir().unwrap();
    let (mut owner, owner_mn) = Engine::init(odir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    owner.authorize_member(&owner_mn, &client_pub).unwrap();
    owner
        .set_acl(&root, &Principal::Key(client_pub.clone()), acl::ACL_RWA)
        .unwrap();
    let library = owner
        .add_node(
            &root,
            pvfs_core::NodeSpec {
                node_type: pvfs_core::TYPE_FOLDER.into(),
                label: "library".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    let bytes_dir = tempfile::tempdir().unwrap();
    let clip_path = bytes_dir.path().join("clip.mkv");
    std::fs::write(&clip_path, b"movie-bytes").unwrap();
    let clip = owner
        .add_node(
            &library,
            pvfs_core::NodeSpec {
                node_type: pvfs_core::TYPE_FILE.into(),
                label: "clip.mkv".into(),
                payload: FilePayload {
                    content_hash: blake3::hash(b"movie-bytes").to_hex().to_string(),
                    size_bytes: 11,
                    mime_type: "video/x-matroska".into(),
                    original_name: "clip.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    owner
        .add_location(
            &clip,
            &pvfs_core::storage::path_to_uri(&std::fs::canonicalize(&clip_path).unwrap())
                .unwrap(),
        )
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

    // ---- consumer: replica + placement + a kept-fresh export + all jobs on
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
            let (_tip, events) = client.log_read(from, 64, "").unwrap();
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
        region: String::new(),
    }
    .save(&rdata)
    .unwrap();
    pvfs_core::sync::set_placement(&rdata, &library, true).unwrap();
    let view = tempfile::tempdir().unwrap();
    pvfs_core::serve::upsert_export(
        &rdata,
        pvfs_core::serve::ExportEntry {
            node: library.clone(),
            mode: "copy".into(),
            fetch: false,
            prune: true,
            dest: view.path().to_path_buf(),
        },
    )
    .unwrap();
    for job in ["follow", "sync", "export"] {
        serve_cfg::set_job(&rdata, job, true).unwrap();
    }
    let jobs = Arc::new(JobsState::load(rdata.clone()).unwrap());
    let shutdown: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let reload: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let runner = {
        let j = Arc::clone(&jobs);
        std::thread::spawn(move || pvfsd::jobs::run(j, shutdown, reload, None))
    };

    // ---- startup passes: bytes fetched from the source, view materialized
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let exported_clip = view.path().join("clip.mkv");
    loop {
        if std::fs::read(&exported_clip).map(|b| b == b"movie-bytes").unwrap_or(false) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "sync+export never materialized the view; rows: {:?}",
            jobs.snapshot()
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    // ---- live: an owner-side mkdir flows through follow → export refresh
    client
        .mkdir(&library, "new-season", |d| {
            crypto::sign_digest(&client_key, d).unwrap()
        })
        .unwrap();
    let new_dir = view.path().join("new-season");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if new_dir.is_dir() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "live change never reached the export view; rows: {:?}",
            jobs.snapshot()
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    shutdown.store(true, Ordering::SeqCst);
    runner.join().unwrap();
}

/// P5.3 wiring: tier and evict run as passes and settle their status rows.
/// On an owned forest with nothing placed and nothing retired, both are
/// clean no-ops — idle, stamped, no error. (The real migrate/reclaim
/// choreography is the fleet test's job; the CLI passes share this code.)
#[test]
fn tier_and_evict_jobs_settle_idle_on_a_quiet_owner() {
    test_config_dir();
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let data_dir = engine.data_dir().to_path_buf();
    drop(engine);
    for job in ["tier", "evict"] {
        serve_cfg::set_job(&data_dir, job, true).unwrap();
    }
    let jobs = Arc::new(JobsState::load(data_dir.clone()).unwrap());
    let shutdown: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let reload: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let runner = {
        let j = Arc::clone(&jobs);
        std::thread::spawn(move || pvfsd::jobs::run(j, shutdown, reload, None))
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let rows = jobs.snapshot();
        let settled = ["tier", "evict"].iter().all(|n| {
            rows.iter().any(|r| {
                r.name == *n && r.state == "idle" && r.last_ok_ms.is_some() && r.last_error.is_none()
            })
        });
        if settled {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "tier/evict never settled: {rows:?}"
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
