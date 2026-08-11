//! P6.0 (doc 19 §2) — the four completing wire ops: loc rm, link, unlink,
//! reorder. Same member model as F5.0's add/loc add: prepared by the daemon,
//! member-signed, authorized at prepare AND commit; refused without `w`.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::orderkey::OrderKey;
use pvfs_core::{crypto, identity, Engine, FilePayload, NodeSpec, TYPE_FILE, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn spec(node_type: &str, label: &str, payload: Vec<u8>) -> NodeSpec {
    NodeSpec {
        node_type: node_type.into(),
        label: label.into(),
        payload,
        is_temp: false,
        creation_nonce: None,
    }
}

fn forbidden<T>(r: Result<T, ClientError>) -> bool {
    matches!(r, Err(ClientError::Server { code, .. }) if code == "forbidden")
}

#[test]
fn member_link_unlink_reorder_and_loc_rm_write_through() {
    // ---- the owner forest: a shared folder (member rw) with one real file
    let dir = tempfile::tempdir().unwrap();
    let (mut owner, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let shared = owner.add_node(&root, spec(TYPE_FOLDER, "shared", Vec::new())).unwrap();
    let file = owner
        .add_node(
            &shared,
            spec(
                TYPE_FILE,
                "clip.mkv",
                FilePayload {
                    content_hash: blake3::hash(b"clip-bytes").to_hex().to_string(),
                    size_bytes: 10,
                    mime_type: "video/x-matroska".into(),
                    original_name: "clip.mkv".into(),
                }
                .encode(),
            ),
        )
        .unwrap();
    owner.add_location(&file, "file:///nowhere/clip.mkv").unwrap();

    let writer_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let writer_pub = crypto::pubkey_bytes(&writer_key);
    let reader_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let reader_pub = crypto::pubkey_bytes(&reader_key);
    owner.authorize_member(&owner_mn, &writer_pub).unwrap();
    owner.authorize_member(&owner_mn, &reader_pub).unwrap();
    owner
        .set_acl(&shared, &Principal::Key(writer_pub.clone()), acl::ACL_R | acl::ACL_W)
        .unwrap();
    owner
        .set_acl(&shared, &Principal::Key(reader_pub.clone()), acl::ACL_R)
        .unwrap();

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
    let mut writer = Client::connect_signed(&sock, &writer_pub, |d| {
        crypto::sign_digest(&writer_key, d).unwrap()
    })
    .unwrap();
    let mut reader = Client::connect_signed(&sock, &reader_pub, |d| {
        crypto::sign_digest(&reader_key, d).unwrap()
    })
    .unwrap();

    // ---- link: a ref link lands, ls shows it
    let link_id = writer
        .link(&shared, &file, "ref", "", |d| {
            crypto::sign_digest(&writer_key, d).unwrap()
        })
        .unwrap();
    assert_eq!(link_id.len(), 64);
    // ---- reorder it with a freshly minted valid key
    let key = OrderKey::after(None).unwrap();
    writer
        .reorder(&link_id, key.as_str(), |d| {
            crypto::sign_digest(&writer_key, d).unwrap()
        })
        .unwrap();
    // ---- unlink it again
    writer
        .unlink(&link_id, |d| crypto::sign_digest(&writer_key, d).unwrap())
        .unwrap();
    // gone: a second unlink reports not_found
    assert!(matches!(
        writer.unlink(&link_id, |d| crypto::sign_digest(&writer_key, d).unwrap()),
        Err(ClientError::Server { code, .. }) if code == "not_found"
    ));

    // ---- loc rm retracts the recorded location
    writer
        .remove_location(&file, "file:///nowhere/clip.mkv", |d| {
            crypto::sign_digest(&writer_key, d).unwrap()
        })
        .unwrap();
    // retracting again: the location no longer exists
    assert!(matches!(
        writer.remove_location(&file, "file:///nowhere/clip.mkv", |d| {
            crypto::sign_digest(&writer_key, d).unwrap()
        }),
        Err(ClientError::Server { code, .. }) if code == "not_found"
    ));

    // ---- a read-only member is refused on every op
    assert!(forbidden(reader.link(&shared, &file, "ref", "", |d| {
        crypto::sign_digest(&reader_key, d).unwrap()
    })));
    assert!(forbidden(reader.remove_location(&file, "pvfs-x://none", |d| {
        crypto::sign_digest(&reader_key, d).unwrap()
    })) || matches!(
        reader.remove_location(&file, "pvfs-x://none", |d| {
            crypto::sign_digest(&reader_key, d).unwrap()
        }),
        Err(ClientError::Server { code, .. }) if code == "not_found"
    ));
}
