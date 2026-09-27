//! PVOS D196 — a replica pointed at a FENCED owner catalogues here, as it
//! does when the owner is unreachable (D183), instead of failing every pass
//! against the refusal. Through a real daemon: the owner answers and serves,
//! but is fenced (D182), so `replica_route` refuses and says why; a watch
//! pass catalogues the new file here with a pending head while the owner's
//! head stays where it was; once a person lifts the fence, the next pass
//! routes again and the pending head commits.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pvfs_core::acl::{self, Principal};
use pvfs_core::log_store::EventRow;
use pvfs_core::{crypto, fence, identity, BindSpec, Engine, HashPolicy, NodeSpec, ReplicaSource, ReplicaStore, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn test_config_dir() -> &'static Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let d = DIR.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", d.path());
        identity::client_identity_mnemonic().unwrap();
        d
    });
    d.path()
}

fn serve_on(daemon: Arc<Daemon>, sock: &Path) {
    let listener = UnixListener::bind(sock).unwrap();
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });
}

/// A replica data dir at `dir`: the owner's log shipped in, and a marker
/// naming `sock` as its source.
fn replica_of(rows: &[EventRow], dir: &Path, sock: &Path) {
    ReplicaStore::open(dir).unwrap().append(rows).unwrap();
    ReplicaSource { transport: "socket".into(), target: sock.to_string_lossy().into_owned(), pin: String::new(), region: String::new() }
        .save(dir)
        .unwrap();
}

/// The owner's committed head for `region` in its log: `(seq, hash)`.
fn owner_head(data: &Path, region: &str) -> (i64, String) {
    let c = rusqlite::Connection::open_with_flags(data.join("index.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    c.query_row("SELECT committed_seq, committed_head FROM regions WHERE node_id = ?1", [region], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
}

#[test]
fn a_replica_pointed_at_a_fenced_owner_catalogues_here_and_commits_once_the_fence_lifts() {
    test_config_dir();
    let cmn = identity::client_identity_mnemonic().unwrap();
    let ckey = identity::device_key(&cmn, "", 0).unwrap();
    let cpub = crypto::pubkey_bytes(&ckey);
    let socks = tempfile::tempdir().unwrap();
    let owner_sock: PathBuf = socks.path().join("owner.sock");

    // The owner: this box's identity may replicate and owns region R.
    let odir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(odir.path()).unwrap();
    let odata = owner.data_dir().to_path_buf();
    let root = owner.identity.root_node_id.clone();
    owner.authorize_member(&mn, &cpub).unwrap();
    owner.set_acl(&root, &Principal::Key(cpub.clone()), acl::ACL_RWA).unwrap();
    let region = owner
        .add_node(&root, NodeSpec { node_type: TYPE_FOLDER.into(), label: "Library".into(), payload: Vec::new(), is_temp: false, creation_nonce: None })
        .unwrap();
    owner.region_mark_as(&region, "catalogue", Some(&Principal::Key(cpub.clone()))).unwrap();
    let rows = owner.log_events(1, owner.log_tip().unwrap() as usize).unwrap();
    owner.close().unwrap();

    // It serves — and is fenced: a follower holds more of the log (D182).
    serve_on(Arc::new(Daemon::new(Engine::open(&odata).unwrap())), &owner_sock);
    let f = fence::Fence {
        reason: fence::Fence::evidence_sentence("10.0.0.8:7431", 99, 7),
        peer: "10.0.0.8:7431".into(),
        peer_seq: 99,
        own_seq: 7,
        ..Default::default()
    };
    assert!(fence::set(&odata, &f).unwrap());

    // The holder: a replica of that owner, binding R, a file on its disk.
    let hdir = tempfile::tempdir().unwrap();
    let hdata = hdir.path().join(".pvfs");
    replica_of(&rows, &hdata, &owner_sock);
    let media = hdir.path().join("media");
    std::fs::create_dir_all(media.join("Shows")).unwrap();
    std::fs::write(media.join("Shows/arrived-after-the-fence.mkv"), b"bytes that arrived after the owner was fenced").unwrap();
    {
        let mut h = Engine::open(&hdata).unwrap();
        h.bind_folder(
            &region,
            BindSpec {
                source_uri: format!("file://{}", media.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
        assert!(h.catalogues_only().unwrap());
        h.close().unwrap();
    }

    // A route through a fenced owner is refused, and says why.
    let refused = match pvfs_client::advertise::replica_route(&hdata, true) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a fenced owner is no route"),
    };
    assert!(refused.contains("the owner is fenced"), "{refused}");
    assert!(refused.contains("10.0.0.8:7431 holds the forest's log to seq 99"), "{refused}");

    // A watch pass: catalogued HERE — the head pending on this box — and not
    // a failed pass against the refusal. The owner's head is untouched.
    let mut route = None;
    {
        let mut h = Engine::open(&hdata).unwrap();
        let reports = pvfs_client::watch::scan_once(&mut h, &mut route, 0)
            .expect("the pass completes here instead of failing against the fence");
        assert!(route.is_none(), "no route was taken");
        assert!(reports.iter().any(|r| r.stats.added >= 1), "the new file is catalogued");
        let pending = h.pending_region_heads().unwrap();
        assert_eq!(pending.len(), 1, "its head is published here, pending");
        assert_eq!((pending[0].0.as_str(), pending[0].1), (region.as_str(), 1));
        h.close().unwrap();
    }
    assert_eq!(owner_head(&odata, &region).0, 0, "nothing is committed through a fenced owner");

    // A person lifts the fence: the next pass routes, and the pending head
    // commits on the owner.
    assert!(fence::clear(&odata).unwrap().is_some());
    {
        let mut h = Engine::open(&hdata).unwrap();
        pvfs_client::watch::scan_once(&mut h, &mut route, 0).expect("a routed pass");
        assert!(route.is_some(), "routed through the owner again");
        h.close().unwrap();
    }
    assert_eq!(owner_head(&odata, &region).0, 1, "the pending head committed once the fence lifted");
    let h = Engine::open(&hdata).unwrap();
    assert!(h.pending_region_heads().unwrap().is_empty(), "nothing pending once the owner holds it");
    h.close().unwrap();
}
