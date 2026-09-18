//! PVOS D174 — the receive plan comes from the running daemon, and asking for
//! it never opens (or folds) the forest.
//!
//! D143's status collector asked the NAS every minute for the mover's plan by
//! running `pvfs view receive --dry-run` inside the production replica: a
//! second process opening the forest, and folding its log under the fold
//! lock, once a minute — D173's standing candidate for the lock the NAS's
//! daemon found held on 2026-09-17. `ReceivePlan` answers the same plan from
//! the daemon's read pool.

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pvfs_client::{Client, ClientError};
use pvfs_core::media::Rules;
use pvfs_core::{crypto, identity, projection, sync, BindSpec, Engine, HashPolicy, NodeSpec, PvfsError, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec {
            node_type: TYPE_FOLDER.into(),
            label: label.into(),
            payload: Vec::new(),
            is_temp: false,
            creation_nonce: None,
        },
    )
    .unwrap()
}

fn region(e: &mut Engine, label: &str, dir: &Path) -> String {
    let root = e.identity.root_node_id.clone();
    let r = folder(e, &root, label);
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

fn write(dir: &Path, rel: &str, bytes: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn applied_mark(data_dir: &Path) -> (u64, String) {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    projection::applied_get(&conn, "").unwrap()
}

fn set_applied_mark(data_dir: &Path, seq: u64, hash: &str) {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    projection::applied_set(&conn, "", seq, hash).unwrap();
}

fn refused(r: Result<pvfs_client::ReceivePlanReply, ClientError>) -> bool {
    matches!(r, Err(ClientError::Server { ref code, .. }) if code == "forbidden")
}

#[test]
fn the_daemon_answers_the_receive_plan_without_opening_the_forest() {
    // The control open below gives up after a second, not a minute (D173).
    std::env::set_var("PVFS_STARTUP_FOLD_WAIT_MS", "1000");
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    let lib = tmp.path().join("lib");
    // One file only staging has (in a folder only staging has), and a staging
    // winner — bigger, newer — over a library copy.
    write(&staging, "Movies/New (2024)/new.mkv", b"new-bytes");
    write(&staging, "Movies/Up (2002)/up.mkv", b"upgraded-much-larger-bytes");
    write(&lib, "Movies/Up (2002)/up.mkv", b"small");
    std::fs::File::options()
        .write(true)
        .open(lib.join("Movies/Up (2002)/up.mkv"))
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(120))
        .unwrap();
    let (mut e, mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let rs = region(&mut e, "Staging", &staging);
    let rl = region(&mut e, "Library", &lib);
    e.set_region_drain(&rs, true).unwrap();
    sync::set_region_receive(e.data_dir(), &rl, true).unwrap();

    // What `view receive --dry-run` computes, straight from the engine.
    let want_folders = e.receive_folders(true).unwrap();
    let (want_items, want_skips) = e.receive_plan(&Rules::default()).unwrap();
    assert_eq!(want_items.len(), 2, "premise: two files to receive: {want_items:?}");
    assert!(want_items.iter().any(|i| i.replaces), "premise: one replaces a library copy");
    assert!(!want_folders.is_empty(), "premise: a folder only staging has");

    let me_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me_key);
    e.authorize_member(&mn, &me_pub).unwrap();
    let data_dir = e.data_dir().to_path_buf();

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(e));
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let mut member = Client::connect_signed(&sock, &me_pub, |d| crypto::sign_digest(&me_key, d).unwrap()).unwrap();

    // 1. The dry run's plan, each file with its size.
    let got = member.receive_plan().expect("a member gets the plan");
    assert_eq!(got.folders, want_folders);
    let mut got_items: Vec<_> =
        got.items.iter().map(|i| (i.path.clone(), i.hash.clone(), i.size, i.region.clone(), i.replaces)).collect();
    let mut want: Vec<_> = want_items
        .iter()
        .map(|i| (i.rel_path.clone(), i.hash.clone(), i.size_bytes, i.dest_region.clone(), i.replaces))
        .collect();
    got_items.sort();
    want.sort();
    assert_eq!(got_items, want);
    let new = got.items.iter().find(|i| i.path == "Movies/New (2024)/new.mkv").expect("the staging-only file");
    assert_eq!(
        (new.size, new.hash.as_str(), new.region.as_str(), new.replaces),
        (9, blake3::hash(b"new-bytes").to_hex().as_str(), rl.as_str(), false)
    );
    let up = got.items.iter().find(|i| i.path == "Movies/Up (2002)/up.mkv").expect("the upgrade");
    assert_eq!((up.size, up.replaces), (26, true));
    assert_eq!(got.reported.len(), want_skips.len());

    // 2. Member-gated, as `serve status` is: library paths are operational
    //    detail. A key that is not enrolled, and no key at all, are refused.
    let stranger = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let stranger_pub = crypto::pubkey_bytes(&stranger);
    let mut other = Client::connect_signed(&sock, &stranger_pub, |d| crypto::sign_digest(&stranger, d).unwrap()).unwrap();
    assert!(refused(other.receive_plan()), "a key that is not a member");
    let mut anon = Client::connect_public(&sock).unwrap();
    assert!(refused(anon.receive_plan()), "an anonymous caller");

    // 3. Nothing opens the forest to answer. Put the cache BEHIND the log (a
    //    fold is due at the next open, D173's technique) and hold the fold
    //    lock as another process would — and the daemon's writer too.
    let (seq, hash) = applied_mark(&data_dir);
    assert!(seq > 0, "premise: the cache had folded the log");
    set_applied_mark(&data_dir, 0, "");
    let fold_lock = projection::hold_fold_lock_for_test(&data_dir).expect("the fold lock, as another process holds it");
    // The control: an open — what the dry run did — has a fold to do now,
    // cannot take the lock, and gives up.
    let control = Engine::open(&data_dir);
    assert!(
        matches!(control, Err(PvfsError::Busy { .. })),
        "premise: in this state an open must fold: {:?}",
        control.map(|_| ())
    );
    let writer = {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let guard = d.hold_writer_for_test();
            std::thread::sleep(Duration::from_secs(6));
            drop(guard);
        })
    };
    std::thread::sleep(Duration::from_millis(300)); // let the holder take it
    let t = Instant::now();
    let again = member.receive_plan().expect("the plan is answered under a held fold lock and writer");
    let took = t.elapsed();
    assert!(took < Duration::from_secs(2), "the plan waited on a lock: {took:?}");
    assert_eq!(again, got, "the same plan, from the read pool");
    assert_eq!(applied_mark(&data_dir).0, 0, "nothing folded: the cache is exactly as far behind as it was left");
    writer.join().unwrap();
    drop(fold_lock);
    set_applied_mark(&data_dir, seq, &hash);
    assert!(member.receive_plan().is_ok());
}
