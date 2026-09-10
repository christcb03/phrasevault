//! D124 item 7 — `purge` and `quality set` route through the owner like every
//! other write. Before this a replica called the engine directly and was
//! refused as read-only (a clean refusal, but a command that could not be
//! run from the box that measures the file).

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_FILE, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn forbidden<T>(r: Result<T, ClientError>) -> bool {
    matches!(r, Err(ClientError::Server { code, .. }) if code == "forbidden")
}

fn spec(node_type: &str, label: &str) -> NodeSpec {
    NodeSpec {
        node_type: node_type.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

fn q(db: &std::path::Path, sql: &str, arg: &str) -> Option<String> {
    let c = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    c.query_row(sql, [arg], |r| r.get::<_, String>(0)).ok()
}

#[test]
fn a_replica_records_quality_and_purges_through_the_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let shared = owner.add_node(&root, spec(TYPE_FOLDER, "shared")).unwrap();
    let clip = owner.add_node(&shared, spec(TYPE_FILE, "clip.mkv")).unwrap();
    // An orphan to purge: linked, then unlinked, under `shared`.
    let stray = owner.add_node(&shared, spec(TYPE_FILE, "stray.mkv")).unwrap();
    let link = owner
        .children(&shared)
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == stray)
        .map(|c| c.link_id)
        .expect("home link");
    owner.remove_link(&link).unwrap();

    let writer_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let writer_pub = crypto::pubkey_bytes(&writer_key);
    let reader_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let reader_pub = crypto::pubkey_bytes(&reader_key);
    owner.authorize_member(&mn, &writer_pub).unwrap();
    owner.authorize_member(&mn, &reader_pub).unwrap();
    owner.set_acl(&shared, &Principal::Key(writer_pub.clone()), acl::ACL_RWA).unwrap();
    owner.set_acl(&stray, &Principal::Key(writer_pub.clone()), acl::ACL_RWA).unwrap();
    owner.set_acl(&shared, &Principal::Key(reader_pub.clone()), acl::ACL_R).unwrap();

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
    let db = dir.path().join("index.db");

    // Quality: a writer records it; the owner's projection carries it, with
    // the measurer's name.
    let mut quality = pvfs_core::media::MediaQuality::default();
    quality.set_resolution("1920x1080").unwrap();
    writer
        .set_quality(&clip, &quality.encode(), "test-probe", |d| crypto::sign_digest(&writer_key, d).unwrap())
        .unwrap();
    assert_eq!(
        q(&db, "SELECT source FROM media_quality WHERE node_id = ?1", &clip).as_deref(),
        Some("test-probe")
    );
    assert!(forbidden(reader.set_quality(&clip, &quality.encode(), "x", |d| {
        crypto::sign_digest(&reader_key, d).unwrap()
    })));

    // Purge: the orphan goes; a linked node is refused as not-orphan; a reader
    // is refused outright.
    writer
        .purge(std::slice::from_ref(&stray), |d| crypto::sign_digest(&writer_key, d).unwrap())
        .unwrap();
    assert_eq!(q(&db, "SELECT id FROM nodes WHERE id = ?1", &stray), None, "purged");
    assert!(q(&db, "SELECT node_id FROM purged_nodes WHERE node_id = ?1", &stray).is_some());
    assert!(writer
        .purge(std::slice::from_ref(&clip), |d| crypto::sign_digest(&writer_key, d).unwrap())
        .is_err(), "a linked node is not an orphan");
    assert!(forbidden(reader.purge(std::slice::from_ref(&clip), |d| {
        crypto::sign_digest(&reader_key, d).unwrap()
    })));
}
