//! D170 — `RenamePath` and `RemoveDir` over the wire: write-gated,
//! `not_found` for a region this box does not hold, `conflict` / `exists` /
//! `not_empty`, and `rename_elsewhere` / `rmdir_elsewhere` — what the view
//! mount calls for the copies other boxes hold — asking box after box.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, ReplicaSource, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn code_is<T>(r: Result<T, ClientError>, want: &str) -> bool {
    matches!(r, Err(ClientError::Server { code, .. }) if code == want)
}

#[test]
fn a_rename_is_write_gated_and_done_on_the_holders_disk() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let dir = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(files.path().join("Shows")).unwrap();
    std::fs::write(files.path().join("Shows/a.mkv"), b"alpha").unwrap();
    std::fs::write(files.path().join("Shows/b.mkv"), b"beta").unwrap();
    std::fs::write(files.path().join("Shows/c.mkv"), b"gamma").unwrap();
    std::fs::create_dir_all(files.path().join("Old/Season 01")).unwrap();
    std::fs::write(files.path().join("Old/Season 01/e1.mkv"), b"episode").unwrap();
    std::fs::create_dir_all(files.path().join("Empty/.@__thumb")).unwrap();
    std::fs::write(files.path().join("Empty/.@__thumb/x.jpg"), b"thumb").unwrap();
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

    let at = |rel: &str| files.path().join(rel);
    let alpha = (h(b"alpha"), 5u64);
    fn file(f: &(String, u64)) -> Option<(&str, u64)> {
        Some((f.0.as_str(), f.1))
    }

    // Default deny: reading a region is not leave to rearrange it.
    assert!(code_is(reader.rename_path(&library, "Shows/a.mkv", "Shows/A.mkv", file(&alpha)), "forbidden"));
    assert!(code_is(reader.remove_dir(&library, "Empty"), "forbidden"));
    // A region this box does not hold: ask another box.
    assert!(code_is(writer.rename_path(&"ab".repeat(32), "Shows/a.mkv", "Shows/A.mkv", file(&alpha)), "not_found"));
    assert!(code_is(writer.remove_dir(&"ab".repeat(32), "Empty"), "not_found"));
    // Not the file that was seen; something in the way; a bad path; a file without its hash.
    let not_alpha = (h(b"something else"), 5u64);
    assert!(code_is(writer.rename_path(&library, "Shows/a.mkv", "Shows/A.mkv", file(&not_alpha)), "conflict"));
    assert!(code_is(writer.rename_path(&library, "Shows/a.mkv", "Shows/b.mkv", file(&alpha)), "exists"));
    assert!(code_is(writer.rename_path(&library, "Shows/a.mkv", "../outside.mkv", file(&alpha)), "bad_input"));
    assert!(code_is(writer.rename_path(&library, "Shows/a.mkv", "Shows/.pvfs-trash/a.mkv", file(&alpha)), "bad_input"));
    assert!(code_is(writer.remove_dir(&library, "Shows"), "not_empty"));
    assert!(at("Shows/a.mkv").is_file() && !at("Shows/A.mkv").exists(), "refusals move nothing");

    // The file that was seen: renamed; asked again, there is nothing left to do.
    assert!(writer.rename_path(&library, "Shows/a.mkv", "Shows/A.mkv", file(&alpha)).unwrap());
    assert_eq!(std::fs::read(at("Shows/A.mkv")).unwrap(), b"alpha");
    assert!(!at("Shows/a.mkv").exists());
    assert!(!writer.rename_path(&library, "Shows/a.mkv", "Shows/A.mkv", file(&alpha)).unwrap());
    // A folder, with what is under it.
    assert!(writer.rename_path(&library, "Old", "New (2020)", None).unwrap());
    assert_eq!(std::fs::read(at("New (2020)/Season 01/e1.mkv")).unwrap(), b"episode");
    // A folder with only litter in it goes; asked again, it is already gone.
    assert!(writer.remove_dir(&library, "Empty").unwrap());
    assert!(!at("Empty").exists());
    assert!(!writer.remove_dir(&library, "Empty").unwrap());

    // What the mount calls: box after box.
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
    let beta = (library.clone(), Some((h(b"beta"), 4u64)));
    pvfs_client::hash_cache::rename_elsewhere(&sources, "Shows/b.mkv", "Shows/B.mkv", &[beta])
        .expect("the second box holds it");
    assert!(at("Shows/B.mkv").is_file() && !at("Shows/b.mkv").exists());
    // two copies, the second refused: the error says how many were done, so the mount can put them back
    let gamma = (library.clone(), Some((h(b"gamma"), 5u64)));
    let stranger = ("cd".repeat(32), Some((h(b"gamma"), 5u64)));
    let (why, done) = pvfs_client::hash_cache::rename_elsewhere(&sources, "Shows/c.mkv", "Shows/C.mkv", &[gamma.clone(), stranger])
        .expect_err("nobody holds the second region");
    assert_eq!(done, 1, "{why}");
    assert!(at("Shows/C.mkv").is_file());
    let back = (library.clone(), Some((h(b"gamma"), 5u64)));
    pvfs_client::hash_cache::rename_elsewhere(&sources, "Shows/C.mkv", "Shows/c.mkv", &[back]).expect("put back");
    assert!(at("Shows/c.mkv").is_file() && !at("Shows/C.mkv").exists());

    std::fs::create_dir_all(at("Hollow")).unwrap();
    pvfs_client::hash_cache::rmdir_elsewhere(&sources, "Hollow", std::slice::from_ref(&library)).expect("removed");
    assert!(!at("Hollow").exists());
    let why = pvfs_client::hash_cache::rmdir_elsewhere(&sources, "Shows", std::slice::from_ref(&library))
        .expect_err("it holds files");
    assert!(why.contains(": not_empty: "), "{why}");
}
