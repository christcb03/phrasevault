//! D129 item 0 — a daemon serves the manifest of a catalogue region it has
//! published, byte for byte what the log's head attests, and nothing else.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn not_held<T>(r: Result<T, ClientError>) -> bool {
    matches!(r, Err(ClientError::Server { code, .. }) if code == "region_not_held")
}

fn region_head(data: &std::path::Path, region: &str) -> (i64, String) {
    let c = rusqlite::Connection::open_with_flags(
        data.join("index.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    c.query_row(
        "SELECT committed_seq, committed_head FROM regions WHERE node_id = ?1",
        [region],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .unwrap()
}

#[test]
fn a_daemon_serves_the_attested_manifest_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(files.path().join("Shows/Empty")).unwrap();
    std::fs::write(files.path().join("a.mkv"), b"aaaa").unwrap();
    std::fs::write(files.path().join("Shows/b.mkv"), b"bbbbbb").unwrap();

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
    let _ = owner.publish_region_snapshot(&library, &mut None).unwrap();
    let _ = owner.commit_region_heads().unwrap();
    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    owner.authorize_member(&mn, &member_pub).unwrap();
    let stranger_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let stranger_pub = crypto::pubkey_bytes(&stranger_key);
    owner.authorize_member(&mn, &stranger_pub).unwrap();
    // The manifest is the region's listing: read rights on it (here granted
    // at the root, which the rights walk carries down to the region).
    owner
        .set_acl(&root, &Principal::Key(member_pub.clone()), acl::ACL_R)
        .unwrap();
    let (seq, head) = region_head(dir.path(), &library);
    assert!(seq >= 1, "premise: the catalogue region has an attested head");
    let file = dir.path().join("regions").join(&library).join(format!("manifest.{seq}"));
    let on_disk = std::fs::read(&file).expect("the published manifest file");

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

    // The bytes are the file, and the file is what the log attests.
    let bytes = member.region_manifest(&library, seq as u64).unwrap();
    assert_eq!(bytes, on_disk);
    assert_eq!(blake3::hash(&bytes).to_hex().as_str(), head);
    assert!(bytes.starts_with(b"pvfs-region-manifest 1\n"));

    // No such file: an unpublished seq, a region this box never catalogued,
    // and a region that is not a catalogue region at all.
    assert!(not_held(member.region_manifest(&library, seq as u64 + 1)));
    assert!(not_held(member.region_manifest(&"00".repeat(32), 1)));
    assert!(not_held(member.region_manifest(&root, 1)));

    // A member with no read grant on the region is refused, not served.
    let mut stranger = Client::connect_signed(&sock, &stranger_pub, |d| {
        crypto::sign_digest(&stranger_key, d).unwrap()
    })
    .unwrap();
    assert!(matches!(
        stranger.region_manifest(&library, seq as u64),
        Err(ClientError::Server { code, .. }) if code == "forbidden"
    ));
}
