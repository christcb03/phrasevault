//! PVOS D183 — the owner out of the daily path, through real daemons: with
//! the forest owner DOWN, a region owner still catalogues its disk and
//! publishes its head locally; a peer takes that head from it (a signed
//! claim), fetches the manifest from it, and its view shows the new file.
//! Then the owner comes back, the pending head commits as one row, and the
//! peer's provisional head gives way to the committed one.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pvfs_client::Client;
use pvfs_core::acl::{self, Principal};
use pvfs_core::log_store::EventRow;
use pvfs_core::{crypto, identity, BindSpec, ClaimOutcome, Engine, HashPolicy, NodeSpec, ReplicaSource, ReplicaStore, TYPE_FOLDER};
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

/// Ship the owner's log from `client` into the replica at `dir` and fold it.
fn follow_once(client: &mut Client, dir: &Path) {
    let mut store = ReplicaStore::open(dir).unwrap();
    let mut from = store.tip().unwrap() + 1;
    loop {
        let (_tip, events) = client.log_read(from, 256, "").unwrap();
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
    drop(store);
    Engine::open(dir).unwrap().close().unwrap();
}

#[test]
fn heads_move_box_to_box_while_the_owner_is_down_and_commit_when_it_is_back() {
    test_config_dir();
    let cmn = identity::client_identity_mnemonic().unwrap();
    let ckey = identity::device_key(&cmn, "", 0).unwrap();
    let cpub = crypto::pubkey_bytes(&ckey);
    let socks = tempfile::tempdir().unwrap();
    let owner_sock: PathBuf = socks.path().join("owner.sock");
    let holder_sock: PathBuf = socks.path().join("holder.sock");

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

    // Two replicas: the holder (binds R on its disk) and a peer. The owner is
    // NOT serving — it is down for everything below until said otherwise.
    let hdir = tempfile::tempdir().unwrap();
    let hdata = hdir.path().join(".pvfs");
    replica_of(&rows, &hdata, &owner_sock);
    let media = hdir.path().join("media");
    std::fs::create_dir_all(media.join("Shows")).unwrap();
    std::fs::write(media.join("Shows/arrived-while-away.mkv"), b"bytes that arrived while the owner was down").unwrap();
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
        // What the watch does with no route: catalogue here, publish here.
        let mut away = pvfs_core::OwnerAway;
        h.scan_routed(None, Some(&mut away), 0).unwrap();
        let pending = h.pending_region_heads().unwrap();
        assert_eq!(pending.len(), 1, "the head is published here and pending");
        assert_eq!((pending[0].0.as_str(), pending[0].1), (region.as_str(), 1));
        let st = h.catalogue_status().unwrap().into_iter().find(|s| s.region == region).unwrap();
        assert_eq!((st.local, st.committed_seq, st.pending), (true, 0, Some(1)), "region ls says so");
        h.close().unwrap();
    }
    let pdir = tempfile::tempdir().unwrap();
    let pdata = pdir.path().join(".pvfs");
    replica_of(&rows, &pdata, &owner_sock);

    // The holder's daemon answers claims and manifests.
    serve_on(Arc::new(Daemon::new(Engine::open(&hdata).unwrap())), &holder_sock);
    let k2 = ckey.clone();
    let mut to_holder = Client::connect_signed(&holder_sock, &cpub, move |d| crypto::sign_digest(&k2, d).unwrap()).unwrap();
    assert!(to_holder.daemon_proto() >= pvfs_client::REGION_CLAIMS_PROTO);
    let claims = to_holder.region_claims().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!((claims[0].region.as_str(), claims[0].seq), (region.as_str(), 1));

    // The peer takes it, fetches the manifest from the holder, and sees the file.
    let mut peer = Engine::open(&pdata).unwrap();
    let body = hex::decode(&claims[0].body).unwrap();
    assert_eq!(peer.accept_region_claim(&body, "holder").unwrap(), ClaimOutcome::Accepted { region: region.clone(), seq: 1 });
    let bytes = to_holder.region_manifest(&region, 1).unwrap();
    assert!(peer.install_region_snapshot(&region, 1, &bytes, "holder").unwrap() >= 1);
    assert!(
        peer.merged_view("Shows").unwrap().iter().any(|v| v.rel_path == "Shows/arrived-while-away.mkv"),
        "the peer's view has the file, with the owner down the whole time"
    );
    let st = peer.catalogue_status().unwrap().into_iter().find(|s| s.region == region).unwrap();
    assert_eq!((st.head_seq, st.committed_seq, st.provisional, st.stale), (1, 0, true, false));
    peer.close().unwrap();

    // The owner comes back. The holder's pending head commits — as ONE row.
    serve_on(Arc::new(Daemon::new(Engine::open(&odata).unwrap())), &owner_sock);
    {
        let h = Engine::open(&hdata).unwrap();
        let (mut client, sign) = pvfs_client::advertise::replica_route(&hdata, true).unwrap().unwrap();
        let signer: &dyn Fn(&[u8; 32]) -> Vec<u8> = &*sign;
        let n = {
            let mut w = pvfs_client::advertise::RoutedScanWriter::new(&hdata, &mut client, signer);
            pvfs_client::watch::commit_pending_heads(&h, &mut w).unwrap()
        };
        assert_eq!(n, 1);
        h.close().unwrap();
    }
    let k3 = ckey.clone();
    let mut to_owner = Client::connect_signed(&owner_sock, &cpub, move |d| crypto::sign_digest(&k3, d).unwrap()).unwrap();
    follow_once(&mut to_owner, &hdata);
    let h = Engine::open(&hdata).unwrap();
    assert!(h.pending_region_heads().unwrap().is_empty(), "nothing pending once the log holds it");
    let st = h.catalogue_status().unwrap().into_iter().find(|s| s.region == region).unwrap();
    assert_eq!((st.committed_seq, st.pending), (1, None));
    h.close().unwrap();

    // The peer follows the owner: the committed head arrives and the
    // provisional row gives way to it (the fold does it).
    follow_once(&mut to_owner, &pdata);
    let peer = Engine::open(&pdata).unwrap();
    let st = peer.catalogue_status().unwrap().into_iter().find(|s| s.region == region).unwrap();
    assert_eq!((st.head_seq, st.committed_seq, st.provisional, st.stale), (1, 1, false, false));
    assert!(peer.merged_view("Shows").unwrap().iter().any(|v| v.rel_path == "Shows/arrived-while-away.mkv"));
    peer.close().unwrap();
}

/// The owner's committed head for `region` in its log: `(seq, hash)`.
fn owner_head(data: &Path, region: &str) -> (i64, String) {
    let c = rusqlite::Connection::open_with_flags(data.join("index.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    c.query_row("SELECT committed_seq, committed_head FROM regions WHERE node_id = ?1", [region], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
}

#[test]
fn a_head_the_owner_already_holds_settles_and_a_superseded_one_is_published_past() {
    test_config_dir();
    let cmn = identity::client_identity_mnemonic().unwrap();
    let ckey = identity::device_key(&cmn, "", 0).unwrap();
    let cpub = crypto::pubkey_bytes(&ckey);
    let socks = tempfile::tempdir().unwrap();
    let owner_sock: PathBuf = socks.path().join("owner.sock");

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

    // The holder catalogues with the owner away: head 1 (A) published here.
    let hdir = tempfile::tempdir().unwrap();
    let hdata = hdir.path().join(".pvfs");
    replica_of(&rows, &hdata, &owner_sock);
    let media = hdir.path().join("media");
    std::fs::create_dir_all(media.join("Shows")).unwrap();
    std::fs::write(media.join("Shows/a.mkv"), b"a-bytes").unwrap();
    {
        let mut h = Engine::open(&hdata).unwrap();
        h.bind_folder(
            &region,
            BindSpec { source_uri: format!("file://{}", media.display()), recursive: true, auto_index: true, extensions: String::new(), hash_policy: HashPolicy::OnAdd },
        )
        .unwrap();
        let mut away = pvfs_core::OwnerAway;
        h.scan_routed(None, Some(&mut away), 0).unwrap();
        assert_eq!(h.pending_region_heads().unwrap().len(), 1);
        h.close().unwrap();
    }

    // But the owner's log already says head 1 is something else (B): a
    // commit whose answer never came back, before the owner went away.
    serve_on(Arc::new(Daemon::new(Engine::open(&odata).unwrap())), &owner_sock);
    let k2 = ckey.clone();
    let mut to_owner = Client::connect_signed(&owner_sock, &cpub, move |d| crypto::sign_digest(&k2, d).unwrap()).unwrap();
    let b = "cd".repeat(32);
    to_owner.commit_region_head(&region, 1, &b, |d| crypto::sign_digest(&ckey, d).unwrap()).unwrap();

    let (mut client, sign) = pvfs_client::advertise::replica_route(&hdata, true).unwrap().unwrap();
    let signer: &dyn Fn(&[u8; 32]) -> Vec<u8> = &*sign;
    {
        let mut h = Engine::open(&hdata).unwrap();
        // The pending head settles (the owner holds seq 1), not an error.
        {
            let mut w = pvfs_client::advertise::RoutedScanWriter::new(&hdata, &mut client, signer);
            assert_eq!(pvfs_client::watch::commit_pending_heads(&h, &mut w).unwrap(), 1);
        }
        assert_eq!(owner_head(&odata, &region), (1, b.clone()), "the owner's head is untouched");
        follow_once(&mut to_owner, &hdata);
        h.close().unwrap();
        h = Engine::open(&hdata).unwrap();
        assert!(h.pending_region_heads().unwrap().is_empty());
        // The next pass, with nothing changed on disk, publishes past B:
        // peers could never install this box's head 1, which is A.
        {
            let mut w = pvfs_client::advertise::RoutedScanWriter::new(&hdata, &mut client, signer);
            h.scan_routed(None, Some(&mut w), 0).unwrap();
        }
        h.close().unwrap();
    }
    let manifest2 = std::fs::read(hdata.join("regions").join(&region).join("manifest.2")).unwrap();
    assert_eq!(owner_head(&odata, &region), (2, blake3::hash(&manifest2).to_hex().to_string()));
    // And once that is folded here, a quiet pass publishes nothing more.
    follow_once(&mut to_owner, &hdata);
    let mut h = Engine::open(&hdata).unwrap();
    {
        let mut w = pvfs_client::advertise::RoutedScanWriter::new(&hdata, &mut client, signer);
        h.scan_routed(None, Some(&mut w), 0).unwrap();
    }
    h.close().unwrap();
    assert_eq!(owner_head(&odata, &region).0, 2);
}
