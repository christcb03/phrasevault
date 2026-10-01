//! PVOS D207 — progress, end to end.
//!
//! 1. A receive's pull counts into the file it holds: a resumed partial from
//!    its length (not counted as this pass's work), then each range as it
//!    lands; a local copy, its size once copied.
//! 2. `serve status`, over the socket as a peer's health probe reads it,
//!    carries a running pass's account — and none once the pass is over.

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use pvfs_client::receive::{partial_path, pull_into_partial_progress};
use pvfs_client::Client;
use pvfs_core::acl::{self, Principal};
use pvfs_core::sync::SWARM_CHUNK;
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, JobProgress, NodeSpec, ReceiveItem, ReplicaSource, TYPE_FOLDER};
use pvfsd::jobs::JobsState;
use pvfsd::{serve, Daemon};

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec { node_type: TYPE_FOLDER.into(), label: label.into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
    )
    .unwrap()
}

/// A daemon over a forest whose staging region holds `bytes` at
/// `Shows/big.mkv`, serving on a socket; this process's client key may read.
fn holder(tmp: &Path, bytes: &[u8]) -> (Arc<Daemon>, std::path::PathBuf, identity::SigningKey, Vec<u8>, String, std::path::PathBuf) {
    let files = tmp.join("staging");
    std::fs::create_dir_all(files.join("Shows")).unwrap();
    std::fs::write(files.join("Shows/big.mkv"), bytes).unwrap();
    let (mut owner, mn) = Engine::init(tmp.join("holder").as_path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let rs = folder(&mut owner, &root, "Staging");
    owner.region_mark_as(&rs, "catalogue", None).unwrap();
    owner
        .bind_folder(
            &rs,
            BindSpec {
                source_uri: format!("file://{}", files.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
    owner.scan_routed(Some(&rs), None, 0).unwrap();
    let key = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
    let pubkey = crypto::pubkey_bytes(&key);
    owner.authorize_member(&mn, &pubkey).unwrap();
    owner.set_acl(&root, &Principal::Key(pubkey.clone()), acl::ACL_R).unwrap();
    let data = owner.data_dir().to_path_buf();
    let sock = tmp.join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(owner));
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    (daemon, sock, key, pubkey, rs, data)
}

#[test]
fn progress_from_the_pull_to_serve_status() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();
    let big: Vec<u8> = (0..(2 * SWARM_CHUNK as usize + 1_000_000)).map(|i| (i % 251) as u8).collect();
    let (daemon, sock, key, pubkey, rs, data) = holder(tmp.path(), &big);
    let src = ReplicaSource { transport: "socket".into(), target: sock.to_string_lossy().into_owned(), pin: String::new(), region: String::new() };
    let lib = tmp.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    let it = ReceiveItem {
        rel_path: "Shows/big.mkv".into(),
        hash: blake3::hash(&big).to_hex().to_string(),
        size_bytes: big.len() as u64,
        mtime_ms: 1_700_000_000_000,
        from_region: rs.clone(),
        dest_region: "ab".repeat(32),
        dest_root: lib.clone(),
        replaces: false,
    };
    let never = AtomicBool::new(false);

    // 1. A partial holding the first chunk: the pull resumes from it.
    std::fs::create_dir_all(partial_path(&it).parent().unwrap()).unwrap();
    std::fs::write(partial_path(&it), &big[..SWARM_CHUNK as usize]).unwrap();
    let p = JobProgress::new();
    p.begin_pass();
    let t = p.begin_file(&it.rel_path, Some(&it.hash), Some(it.size_bytes), 0);
    let chunks = pull_into_partial_progress(&it, None, std::slice::from_ref(&src), &never, 2, Some((&p, t)))
        .unwrap()
        .expect("not cancelled");
    assert_eq!(chunks.len(), 3);
    let s = p.snapshot().unwrap();
    assert_eq!(s.current.len(), 1, "in hand until the caller places it");
    assert_eq!(s.current[0].bytes, big.len() as u64, "the file's bytes: the resumed chunk and the rest");
    assert_eq!(s.bytes_done, big.len() as u64 - SWARM_CHUNK, "this pass's work: what it pulled, not what it found");
    assert_eq!(s.current[0].hash.as_deref(), Some(it.hash.as_str()));
    p.end_file(t, true);
    let s = p.snapshot().unwrap();
    assert_eq!((s.files_done, s.current.len()), (1, 0));

    // A local copy counts its whole size, once copied.
    let _ = std::fs::remove_file(partial_path(&it));
    let local = tmp.path().join("staging/Shows/big.mkv");
    p.begin_pass();
    let t = p.begin_file(&it.rel_path, Some(&it.hash), Some(it.size_bytes), 0);
    pull_into_partial_progress(&it, Some(&local), &[], &never, 1, Some((&p, t))).unwrap().unwrap();
    assert_eq!(p.snapshot().unwrap().bytes_done, big.len() as u64);
    p.end_pass();

    // 2. `serve status` carries the pass in flight, as a peer's probe reads it.
    let state = Arc::new(JobsState::load(data.clone()).unwrap());
    daemon.attach_jobs(Arc::clone(&state));
    let k = key.clone();
    let mut client = Client::connect_signed(&sock, &pubkey, move |d| crypto::sign_digest(&k, d).unwrap()).unwrap();
    let st = client.serve_status_full().unwrap();
    assert!(st.jobs.iter().all(|j| j.progress.is_none()), "no pass, no account");
    let watch = state.progress("watch").expect("the watch keeps an account");
    watch.begin_pass();
    watch.phase("hashing");
    let t = watch.begin_file("/mnt/local/Media/TV/Show/e05.mkv", None, Some(40_000_000_000), 0);
    watch.file_bytes(t, 12_000_000_000);
    watch.file_done(5_000_000);
    let st = client.serve_status_full().unwrap();
    let row = st.jobs.iter().find(|j| j.name == "watch").unwrap();
    let pw = row.progress.as_ref().expect("the running pass's account, on the wire");
    assert_eq!((pw.phase.as_deref(), pw.files_done, pw.bytes_done), (Some("hashing"), 1, 12_005_000_000));
    assert_eq!(pw.current[0].path, "/mnt/local/Media/TV/Show/e05.mkv");
    assert_eq!((pw.current[0].bytes, pw.current[0].size), (12_000_000_000, Some(40_000_000_000)));
    assert!(pw.started_ms > 0 && pw.advanced_ms >= pw.started_ms);
    assert!(st.jobs.iter().filter(|j| j.name != "watch").all(|j| j.progress.is_none()));
    watch.end_pass();
    let st = client.serve_status_full().unwrap();
    assert!(st.jobs.iter().all(|j| j.progress.is_none()), "the pass is over");
}
