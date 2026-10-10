//! PVOS D231 — the runner's trash step goes past a bucket it cannot remove,
//! and `serve status` says which bucket, which path and whose folder.
//!
//! 2026-10-09 8:01 PM: mediabox's holder could not remove two root-made
//! buckets (a `sudo pvfs trash put`). The step's `purge_trash` returned at
//! the first, so that region's other buckets waited behind it, and its trash
//! was no longer reported (its record froze), with only `I/O error during
//! purge trash bucket: Permission denied` in the journal to say why.
//!
//! A read-only folder stands in for root's (this needs a non-root test
//! user, as the pipeline's is). Its own test binary: it sets process-wide
//! environment (the step's interval, the config dir).

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pvfs_client::{Client, ServeStatusReply};
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};
use pvfsd::jobs::JobsState;
use pvfsd::{serve, Daemon};

fn region(e: &mut Engine, label: &str, dir: &Path) -> String {
    let root = e.identity.root_node_id.clone();
    let r = e
        .add_node(
            &root,
            NodeSpec { node_type: TYPE_FOLDER.into(), label: label.into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
        )
        .unwrap();
    e.region_mark_as(&r, "catalogue", None).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    e.bind_folder(
        &r,
        BindSpec {
            source_uri: format!("file://{}", dir.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&r), None, 0).unwrap();
    r
}

fn write(p: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn bucket(root: &Path, day: u64, bytes: usize) -> std::path::PathBuf {
    let b = root.join(".pvfs-trash").join(day.to_string());
    write(&b.join("TV/Show/Season 1/ep.mkv"), &vec![9u8; bytes]);
    b
}

fn set_mode(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn status_until(c: &mut Client, secs: u64, what: &str, done: impl Fn(&ServeStatusReply) -> bool) -> ServeStatusReply {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let s = c.serve_status_full().unwrap();
        if done(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "{what}: never happened; last trash {:?}", s.trash);
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_trash_step_reports_a_stuck_bucket_and_still_purges_the_rest() {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipped: root removes from a read-only folder anyway");
        return;
    }
    std::env::set_var("PVFS_TRASH_EVERY_MS", "300");
    std::env::set_var("PVFS_STARTUP_FOLD_WAIT_MS", "1000");
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());

    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("local");
    write(&local.join("TV/Show/Season 1/e1.mkv"), b"one");
    let (mut e, mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let r = region(&mut e, "mediabox-local", &local);
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 86_400;
    let stuck = bucket(&local, d - 20, 3_000);
    let locked = stuck.join("TV/Show/Season 1");
    set_mode(&locked, 0o555);
    let newer = bucket(&local, d - 10, 2_000);
    let today = bucket(&local, d, 1_000);

    let me_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me_key);
    e.authorize_member(&mn, &me_pub).unwrap();
    let data_dir = e.data_dir().to_path_buf();
    let daemon = Arc::new(Daemon::new(e));
    let jobs = Arc::new(JobsState::load(data_dir.clone()).unwrap());
    daemon.attach_jobs(Arc::clone(&jobs));
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("pvfsd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let mut member = Client::connect_signed(&sock, &me_pub, |dg| crypto::sign_digest(&me_key, dg).unwrap()).unwrap();
    let shutdown: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let reload: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let runner = {
        let (j, dm) = (Arc::clone(&jobs), Arc::clone(&daemon));
        std::thread::spawn(move || pvfsd::jobs::run(j, shutdown, reload, Some(dm)))
    };

    // 1. The step reports the region, the stuck bucket in it, and has purged
    //    the newer bucket past retention all the same.
    let s = status_until(&mut member, 5, "the region reported", |s| s.trash.iter().any(|t| t.region == r));
    let t = s.trash.iter().find(|t| t.region == r).unwrap();
    assert!(!newer.exists(), "the newer bucket past retention is not kept behind the stuck one");
    assert!(today.exists(), "retention keeps today's");
    assert_eq!(t.stuck.len(), 1, "{t:?}");
    let b = &t.stuck[0];
    assert_eq!(b.day, d - 20);
    assert_eq!(b.bucket, stuck.display().to_string());
    assert_eq!(b.path, locked.join("ep.mkv").display().to_string(), "{b:?}");
    assert!(b.error.contains("Permission denied"), "{b:?}");
    let me = pvfs_core::sync::process_user();
    assert_eq!((b.folder_owner.as_deref(), b.daemon_user.as_deref()), (Some(me.as_str()), Some(me.as_str())), "{b:?}");
    assert_eq!((b.left_bytes, t.buckets, t.oldest_day), (3_000, 2, Some(d - 20)), "the stuck bucket is still kept: {t:?}");

    // 2. Fixed by hand (the chown on mediabox): a later step removes it and
    //    the report no longer lists it.
    set_mode(&locked, 0o755);
    let s = status_until(&mut member, 5, "the stuck bucket gone", |s| {
        s.trash.iter().any(|t| t.region == r && t.stuck.is_empty())
    });
    let t = s.trash.iter().find(|t| t.region == r).unwrap();
    assert!(!stuck.exists());
    assert_eq!((t.buckets, t.oldest_day), (1, Some(d)), "{t:?}");

    shutdown.store(true, Ordering::SeqCst);
    let _ = runner.join();
}
