//! PVOS D252 — a routed write goes out on a live connection. A replica's
//! watch keeps its connection to the owner from pass to pass; when the owner
//! closed it in between (a restart), the next pass used to fail with
//! `connection closed` and only the pass after that dialed again. Now the
//! writer sees the closed connection before it writes, dials again, and the
//! pass commits. Through a real owner daemon behind a relay socket, so the
//! test can close a live connection from the far end the way a restart does.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pvfs_core::acl::{self, Principal};
use pvfs_core::log_store::EventRow;
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, ReplicaSource, ReplicaStore, TYPE_FOLDER};
use pvfs_log::testing::GlobalCapture;
use pvfs_log::Value;
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

/// A Unix socket in front of the owner's: every connection to it is piped to
/// the owner. `cut` closes the live ones from this (the owner's) side; `refuse`
/// makes new ones fail, as an owner that is still down does.
struct Relay {
    live: Arc<Mutex<Vec<UnixStream>>>,
    refusing: Arc<AtomicBool>,
}

impl Relay {
    fn start(at: &Path, owner: PathBuf) -> Relay {
        let listener = UnixListener::bind(at).unwrap();
        let live = Arc::new(Mutex::new(Vec::new()));
        let refusing = Arc::new(AtomicBool::new(false));
        let (l, r) = (Arc::clone(&live), Arc::clone(&refusing));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(down) = conn else { continue };
                if r.load(Ordering::SeqCst) {
                    drop(down);
                    continue;
                }
                let up = UnixStream::connect(&owner).unwrap();
                l.lock().unwrap().extend([down.try_clone().unwrap(), up.try_clone().unwrap()]);
                pipe(down.try_clone().unwrap(), up.try_clone().unwrap());
                pipe(up, down);
            }
        });
        Relay { live, refusing }
    }

    fn cut(&self) {
        for s in self.live.lock().unwrap().drain(..) {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        // the close travels to the replica's socket
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn pipe(mut from: UnixStream, mut to: UnixStream) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to.shutdown(std::net::Shutdown::Write);
    });
}

fn replica_of(rows: &[EventRow], dir: &Path, sock: &Path) {
    ReplicaStore::open(dir).unwrap().append(rows).unwrap();
    ReplicaSource { transport: "socket".into(), target: sock.to_string_lossy().into_owned(), pin: String::new(), region: String::new() }
        .save(dir)
        .unwrap();
}

fn owner_head(data: &Path, region: &str) -> i64 {
    let c = rusqlite::Connection::open_with_flags(data.join("index.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    c.query_row("SELECT committed_seq FROM regions WHERE node_id = ?1", [region], |r| r.get(0)).unwrap()
}

#[test]
fn a_connection_the_owner_closed_between_passes_is_dialed_again_before_the_write() {
    let cap = GlobalCapture::start();
    test_config_dir();
    let cmn = identity::client_identity_mnemonic().unwrap();
    let ckey = identity::device_key(&cmn, "", 0).unwrap();
    let cpub = crypto::pubkey_bytes(&ckey);
    let socks = tempfile::tempdir().unwrap();
    let owner_sock = socks.path().join("owner.sock");
    let relay_sock = socks.path().join("relay.sock");

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
    let listener = UnixListener::bind(&owner_sock).unwrap();
    let daemon = Arc::new(Daemon::new(Engine::open(&odata).unwrap()));
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });
    let relay = Relay::start(&relay_sock, owner_sock.clone());

    // The holder: a replica of that owner, reached through the relay, binding R.
    let hdir = tempfile::tempdir().unwrap();
    let hdata = hdir.path().join(".pvfs");
    replica_of(&rows, &hdata, &relay_sock);
    let media = hdir.path().join("media");
    std::fs::create_dir_all(media.join("Shows")).unwrap();
    std::fs::write(media.join("Shows/one.mkv"), b"the first file").unwrap();
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
        h.close().unwrap();
    }
    let pass = |route: &mut Option<_>| {
        let mut h = Engine::open(&hdata).unwrap();
        let r = pvfs_client::watch::scan_once(&mut h, route, 0);
        h.close().unwrap();
        r
    };

    // A routed pass commits the head through the relay.
    let mut route = None;
    pass(&mut route).expect("the first routed pass");
    assert!(route.is_some(), "routed through the owner");
    assert_eq!(owner_head(&odata, &region), 1);
    assert!(route.as_ref().map(|(c, _)| c.stale()).unwrap().is_none(), "a live connection is not stale");

    // The owner closes that connection while it sits idle, as a restart does.
    relay.cut();
    assert_eq!(route.as_ref().map(|(c, _)| c.stale()).unwrap(), Some("peer_closed"));

    // The next pass, on the same route: dialed again before the write, and
    // the head commits. Before D252 this pass failed with `connection closed`.
    std::fs::write(media.join("Shows/two.mkv"), b"the second file").unwrap();
    pass(&mut route).expect("the pass after the close commits instead of failing");
    assert_eq!(owner_head(&odata, &region), 2, "the new head is on the owner");
    assert!(route.as_ref().map(|(c, _)| c.stale()).unwrap().is_none(), "the route holds the new connection");
    let lines = cap.events("pvfs.route.redialed");
    assert_eq!(lines.len(), 1, "one line for one redial");
    assert_eq!(lines[0].severity, pvfs_log::Severity::Debug, "expected and healed: debug");
    let reason = lines[0].fields.iter().find(|f| f.name == "reason").map(|f| &f.value);
    assert!(matches!(reason, Some(Value::Str(s)) if s == "peer_closed"), "{reason:?}");

    // An owner that is still down after the close: the pass fails as an
    // unreachable owner's does (a transient `Io`), and quarantines nothing.
    relay.refusing.store(true, Ordering::SeqCst);
    relay.cut();
    std::fs::write(media.join("Shows/three.mkv"), b"the third file").unwrap();
    let err = pass(&mut route).expect_err("no owner to write through");
    assert!(matches!(err, pvfs_core::PvfsError::Io { .. }), "{err:?}");
    assert!(err.to_string().contains("dialing again failed"), "{err}");
    assert_eq!(owner_head(&odata, &region), 2);

    // The owner back: the next pass commits the third file's head, and
    // nothing was quarantined for the lost connection.
    relay.refusing.store(false, Ordering::SeqCst);
    let reports = pass(&mut route).expect("the owner answers again");
    assert!(reports.iter().all(|r| r.stats.quarantined.is_empty() && r.stats.needs_attention == 0), "{reports:?}");
    assert_eq!(owner_head(&odata, &region), 3, "the head the failed pass could not commit");
}
