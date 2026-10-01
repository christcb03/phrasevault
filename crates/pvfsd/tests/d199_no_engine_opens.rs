//! PVOS D199 — the efficiency half: with the daemon's writer handed to the
//! job runner, no job opens an engine (so none folds the log to open one).
//! The owner runs watch, catalogue, reclaim, resolve, receive and health; a
//! replica runs follow, watch and catalogue; both through every job's first
//! pass. The process's counters (`pvfs_core::writer::COUNTERS`) say how many
//! engines were opened meanwhile: none. Its own test binary, since the
//! counters are the process's.

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, serve as serve_cfg, BindSpec, Engine, HashPolicy, NodeSpec, ReplicaSource, ReplicaStore, TYPE_FOLDER};
use pvfsd::jobs::JobsState;
use pvfsd::{serve, Daemon};

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec { node_type: TYPE_FOLDER.into(), label: label.into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
    )
    .unwrap()
}

fn bind(e: &mut Engine, region: &str, dir: &Path) {
    e.bind_folder(
        &region.to_string(),
        BindSpec {
            source_uri: format!("file://{}", dir.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
}

/// Run `daemon`'s jobs until every one of `jobs` has completed a pass (or
/// `wait` for the watch's rows), then stop the runner.
fn run_jobs_until_each_passed(daemon: &Arc<Daemon>, data: &Path, jobs: &[&str], done: impl Fn() -> bool) {
    for j in jobs {
        serve_cfg::set_job(data, j, true).unwrap();
    }
    let state = Arc::new(JobsState::load(data.to_path_buf()).unwrap());
    daemon.attach_jobs(Arc::clone(&state));
    let shutdown: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let reload: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let runner = {
        let (s, d) = (Arc::clone(&state), Arc::clone(daemon));
        std::thread::spawn(move || pvfsd::jobs::run(s, shutdown, reload, Some(d)))
    };
    let t = Instant::now();
    loop {
        let rows = state.snapshot();
        let passed = jobs
            .iter()
            .all(|j| rows.iter().any(|r| r.name == *j && r.last_ok_ms.is_some()));
        if passed && done() {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(120), "the jobs did not all pass: {rows:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
    shutdown.store(true, Ordering::SeqCst);
    runner.join().unwrap();
}

#[test]
fn no_job_opens_an_engine() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let cmn = identity::client_identity_mnemonic().unwrap();
    let cpub = crypto::pubkey_bytes(&identity::device_key(&cmn, "", 0).unwrap());

    // The owner: a catalogue region of its own, bound on its disk.
    let odir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(odir.path().join("forest").as_path()).unwrap();
    let odata = owner.data_dir().to_path_buf();
    let root = owner.identity.root_node_id.clone();
    owner.authorize_member(&mn, &cpub).unwrap();
    owner.set_acl(&root, &Principal::Key(cpub.clone()), acl::ACL_RWA).unwrap();
    let media = odir.path().join("media");
    std::fs::create_dir_all(media.join("Films")).unwrap();
    for i in 0..20 {
        std::fs::write(media.join(format!("Films/f{i}.mkv")), format!("film {i}")).unwrap();
    }
    let local = folder(&mut owner, &root, "Local");
    owner.region_mark_as(&local, "catalogue", None).unwrap();
    bind(&mut owner, &local, &media);
    let seed = owner.log_events(1, owner.log_tip().unwrap() as usize).unwrap();
    let socks = tempfile::tempdir().unwrap();
    let osock = socks.path().join("owner.sock");
    let odaemon = Arc::new(Daemon::new(owner));
    {
        let (l, d) = (UnixListener::bind(&osock).unwrap(), Arc::clone(&odaemon));
        std::thread::spawn(move || {
            let _ = serve(l, d);
        });
    }

    // The replica: follows the owner.
    let rdir = tempfile::tempdir().unwrap();
    let rdata = rdir.path().join(".pvfs");
    ReplicaStore::open(&rdata).unwrap().append(&seed).unwrap();
    ReplicaSource { transport: "socket".into(), target: osock.to_string_lossy().into_owned(), pin: String::new(), region: String::new() }
        .save(&rdata)
        .unwrap();
    let rdaemon = Arc::new(Daemon::new(Engine::open(&rdata).unwrap()));

    let (opens, views, folds, _) = pvfs_core::writer::COUNTERS.read();
    let rows_here = |data: &Path| {
        let v = Engine::open_read_view(data).unwrap();
        v.region_entries(&local).map(|r| r.len()).unwrap_or(0)
    };
    run_jobs_until_each_passed(
        &odaemon,
        &odata,
        &["watch", "catalogue", "reclaim", "resolve", "receive", "health"],
        || rows_here(&odata) == 21,
    );
    // Something for the replica's follower to fold: a folder made on the owner.
    odaemon.writer().step("test: mkdir", |e| folder(e, &root, "Made while the replica followed"));
    let otip = odaemon.writer().step("test: tip", |e| e.log_tip().unwrap());
    run_jobs_until_each_passed(&rdaemon, &rdata, &["follow", "watch", "catalogue"], || {
        Engine::open_read_view(&rdata).unwrap().log_tip().unwrap() == otip
    });

    let (opens2, views2, folds2, _) = pvfs_core::writer::COUNTERS.read();
    println!("D199: engine opens {}, read views {}, folds {}", opens2 - opens, views2 - views, folds2 - folds);
    assert_eq!(opens2 - opens, 0, "a job opened an engine of its own");
    assert!(views2 > views, "the jobs read through views");
    assert!(folds2 > folds, "the follower folded, through the writer");
    // And the replica's projection holds what it followed.
    let view = Engine::open_read_view(&rdata).unwrap();
    assert!(view.children(&root).unwrap().iter().any(|c| c.label == "Made while the replica followed"));
}
