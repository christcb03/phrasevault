//! D130 items 1–2 — a daemon streams the bytes of a content hash it
//! catalogues, read-gated, and the read-through lands them verified in
//! the hash store — or names the box that served the wrong bytes.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::fetch::SwarmProgress;
use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, sync, BindSpec, Engine, HashPolicy, NodeSpec, ReplicaSource, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn code_is<T>(r: Result<T, ClientError>, want: &str) -> bool {
    matches!(r, Err(ClientError::Server { code, .. }) if code == want)
}

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

#[test]
fn bytes_by_hash_are_served_gated_and_land_verified() {
    // The client identity the read-through dials with lives under XDG.
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let dir = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(files.path().join("Shows")).unwrap();
    std::fs::write(files.path().join("Shows/a.mkv"), b"alpha-bytes-in-a-region").unwrap();
    std::fs::write(files.path().join("Shows/b.mkv"), b"beta").unwrap();
    let h_a = blake3::hash(b"alpha-bytes-in-a-region").to_hex().to_string();
    let h_b = blake3::hash(b"beta").to_hex().to_string();

    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let library = folder(&mut owner, &root, "Library");
    owner.region_mark_as(&library, "catalogue", None).unwrap();
    owner
        .bind_folder(
            &library,
            BindSpec {
                source_uri: format!("file://{}", files.path().display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
    owner.scan_routed(Some(&library), None, 0).unwrap();
    assert!(owner.local_path_for_hash(&h_a).unwrap().is_some(), "premise: the scan hashed a.mkv");

    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    owner.authorize_member(&mn, &member_pub).unwrap();
    owner.set_acl(&root, &Principal::Key(member_pub.clone()), acl::ACL_R).unwrap();
    let stranger_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let stranger_pub = crypto::pubkey_bytes(&stranger_key);
    owner.authorize_member(&mn, &stranger_pub).unwrap();
    // The read-through's own identity, admitted as a reader too.
    let me_key = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me_key);
    owner.authorize_member(&mn, &me_pub).unwrap();
    owner.set_acl(&root, &Principal::Key(me_pub.clone()), acl::ACL_R).unwrap();

    // A second forest: the box that will read through (its data dir holds
    // the hash store). Any data dir will do — the store is per box.
    let reader_dir = tempfile::tempdir().unwrap();
    let (reader, _) = Engine::init(reader_dir.path()).unwrap();
    reader.close().unwrap();

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(owner));
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let mut member = Client::connect_signed(&sock, &member_pub, |d| {
        crypto::sign_digest(&member_key, d).unwrap()
    })
    .unwrap();

    // Item 1: the bytes, whole and ranged; unknown hash; no grant.
    let mut out = Vec::new();
    assert_eq!(member.cat_hash_range(&h_a, 0, 0, &mut out).unwrap(), 23);
    assert_eq!(out, b"alpha-bytes-in-a-region");
    let mut part = Vec::new();
    assert_eq!(member.cat_hash_range(&h_a, 6, 5, &mut part).unwrap(), 5);
    assert_eq!(part, b"bytes");
    assert!(code_is(member.cat_hash_range(&"00".repeat(32), 0, 0, &mut Vec::new()), "not_found"));
    let mut stranger = Client::connect_signed(&sock, &stranger_pub, |d| {
        crypto::sign_digest(&stranger_key, d).unwrap()
    })
    .unwrap();
    assert!(code_is(stranger.cat_hash_range(&h_a, 0, 0, &mut Vec::new()), "forbidden"));

    // Item 2: the read-through lands a verified copy in the reader's store.
    let src = ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    };
    let progress = SwarmProgress::default();
    pvfs_client::fetch::fetch_by_hash_from(reader_dir.path(), &h_a, 23, std::slice::from_ref(&src), &progress);
    assert!(!progress.failed(), "the read-through must succeed");
    let landed = sync::hash_store_lookup(reader_dir.path(), &h_a).unwrap().expect("in the hash store");
    assert_eq!(std::fs::read(&landed).unwrap(), b"alpha-bytes-in-a-region");
    assert!(!landed.with_extension("partial").exists(), "no partial left behind");

    // A size mismatch on disk (a half-written file) is not served …
    std::fs::write(files.path().join("Shows/b.mkv"), b"be").unwrap();
    assert!(code_is(member.cat_hash_range(&h_b, 0, 0, &mut Vec::new()), "not_found"));
    // … and a holder whose bytes do not hash to what was asked is refused
    // and named: the row still says `beta`, the disk says `bet!`.
    std::fs::write(files.path().join("Shows/b.mkv"), b"bet!").unwrap();
    let progress = SwarmProgress::default();
    pvfs_client::fetch::fetch_by_hash_from(reader_dir.path(), &h_b, 4, std::slice::from_ref(&src), &progress);
    assert!(progress.failed(), "wrong bytes must not land");
    let why = progress.error().unwrap_or_default();
    assert!(why.contains(&sock.to_string_lossy().into_owned()) && why.contains("hash"), "names the box and the mismatch: {why}");
    assert!(sync::hash_store_lookup(reader_dir.path(), &h_b).unwrap().is_none());
    assert!(!sync::hash_store_path(reader_dir.path(), &h_b).unwrap().with_extension("partial").exists());
}
