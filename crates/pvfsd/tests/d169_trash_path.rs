//! D169 — `TrashPath` over the wire: write-gated, `not_found` for a region this
//! box does not hold, `conflict` for a file that changed, and
//! `trash_elsewhere` — what the view mount's `unlink` calls for the copies
//! other boxes hold — asking box after box.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, sync, BindSpec, Engine, HashPolicy, NodeSpec, ReplicaSource, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn code_is<T>(r: Result<T, ClientError>, want: &str) -> bool {
    matches!(r, Err(ClientError::Server { code, .. }) if code == want)
}

#[test]
fn a_delete_is_write_gated_and_goes_to_the_holders_trash() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let dir = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(files.path().join("Shows")).unwrap();
    std::fs::write(files.path().join("Shows/a.mkv"), b"alpha").unwrap();
    std::fs::write(files.path().join("Shows/b.mkv"), b"beta").unwrap();
    std::fs::write(files.path().join("Shows/c.mkv"), b"gamma").unwrap();
    let h = |b: &[u8]| blake3::hash(b).to_hex().to_string();

    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let library = owner
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Library".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
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

    let key = |owner: &mut Engine, rights: u8| {
        let k = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
        let p = crypto::pubkey_bytes(&k);
        owner.authorize_member(&mn, &p).unwrap();
        owner.set_acl(&root, &Principal::Key(p.clone()), rights).unwrap();
        (k, p)
    };
    let (writer_key, writer_pub) = key(&mut owner, acl::ACL_R | acl::ACL_W);
    let (reader_key, reader_pub) = key(&mut owner, acl::ACL_R);
    // what `trash_elsewhere` dials as: this box's client identity
    let me_key = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me_key);
    owner.authorize_member(&mn, &me_pub).unwrap();
    owner.set_acl(&root, &Principal::Key(me_pub), acl::ACL_R | acl::ACL_W).unwrap();

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(owner));
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });
    let connect = |k: &pvfs_core::identity::SigningKey, p: &[u8]| {
        let k = k.clone();
        Client::connect_signed(&sock, p, move |d| crypto::sign_digest(&k, d).unwrap()).unwrap()
    };
    let mut writer = connect(&writer_key, &writer_pub);
    let mut reader = connect(&reader_key, &reader_pub);

    // Default deny: reading a region is not leave to empty it.
    assert!(code_is(reader.trash_path(&library, "Shows/a.mkv", &h(b"alpha")), "forbidden"));
    // A region this box does not hold: ask another box.
    assert!(code_is(writer.trash_path(&"ab".repeat(32), "Shows/a.mkv", &h(b"alpha")), "not_found"));
    // Not the file that was seen.
    assert!(code_is(writer.trash_path(&library, "Shows/a.mkv", &h(b"something else")), "conflict"));
    assert!(code_is(writer.trash_path(&library, "../outside", &h(b"alpha")), "bad_input"));
    assert!(files.path().join("Shows/a.mkv").is_file(), "refusals move nothing");

    // The file that was seen: to the trash; asked again, it is already gone.
    assert!(writer.trash_path(&library, "Shows/a.mkv", &h(b"alpha")).unwrap());
    assert!(!files.path().join("Shows/a.mkv").exists());
    assert!(!writer.trash_path(&library, "Shows/a.mkv", &h(b"alpha")).unwrap());
    let trashed: Vec<String> = sync::list_trash(files.path()).into_iter().map(|t| t.rel_path).collect();
    assert_eq!(trashed, vec!["Shows/a.mkv"]);

    // What the mount calls: box after box. A box that is not there is
    // skipped; the one that holds the region does it; a region nobody holds
    // is an error that says so.
    let here = ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    };
    let nobody = ReplicaSource {
        target: sockdir.path().join("nobody.sock").to_string_lossy().into_owned(),
        ..here.clone()
    };
    let sources = [nobody, here];
    pvfs_client::hash_cache::trash_elsewhere(
        &sources,
        "Shows/b.mkv",
        &[(library.clone(), h(b"beta"))],
    )
    .expect("the second box holds it");
    assert!(!files.path().join("Shows/b.mkv").exists());
    let why = pvfs_client::hash_cache::trash_elsewhere(&sources, "Shows/c.mkv", &[("cd".repeat(32), h(b"gamma"))])
        .expect_err("nobody holds that region");
    assert!(why.contains("cdcdcdcd") || why.contains("nobody.sock"), "{why}");
    let why = pvfs_client::hash_cache::trash_elsewhere(&sources, "Shows/c.mkv", &[(library.clone(), h(b"not gamma"))])
        .expect_err("a changed file is an error, not a skip");
    assert!(why.contains("conflict"), "{why}");
    assert!(files.path().join("Shows/c.mkv").is_file());
}
