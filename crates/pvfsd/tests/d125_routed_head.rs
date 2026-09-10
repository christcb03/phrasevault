//! D125 items 7–8 — a region owner publishes its catalogue head THROUGH the
//! forest owner: the one routed write ownership grants, and the only one.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::Principal;
use pvfs_core::{crypto, identity, Engine, NodeSpec, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn forbidden<T>(r: Result<T, ClientError>) -> bool {
    matches!(r, Err(ClientError::Server { code, .. }) if code == "forbidden")
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

fn last_kind(data: &std::path::Path) -> String {
    let c = rusqlite::Connection::open_with_flags(
        data.join("log.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    c.query_row("SELECT kind FROM events ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn a_region_owner_publishes_its_head_through_the_forest_owner_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
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
    let holder_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let holder_pub = crypto::pubkey_bytes(&holder_key);
    let other_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let other_pub = crypto::pubkey_bytes(&other_key);
    owner.authorize_member(&mn, &holder_pub).unwrap();
    owner.authorize_member(&mn, &other_pub).unwrap();
    // `region mark --catalogue --owner key:<holder>` — the grant IS the ownership.
    owner
        .region_mark_as(&library, "catalogue", Some(&Principal::Key(holder_pub.clone())))
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
    let mut holder = Client::connect_signed(&sock, &holder_pub, |d| {
        crypto::sign_digest(&holder_key, d).unwrap()
    })
    .unwrap();
    let mut other = Client::connect_signed(&sock, &other_pub, |d| {
        crypto::sign_digest(&other_key, d).unwrap()
    })
    .unwrap();
    let hash = "ab".repeat(32);

    // The owner box publishes; the forest owner's projection shows it.
    holder
        .commit_region_head(&library, 1, &hash, |d| crypto::sign_digest(&holder_key, d).unwrap())
        .unwrap();
    assert_eq!(region_head(dir.path(), &library), (1, hash.clone()));
    assert_eq!(last_kind(dir.path()), "SubRegionHead");

    // A head that does not advance is refused.
    assert!(holder
        .commit_region_head(&library, 1, &hash, |d| crypto::sign_digest(&holder_key, d).unwrap())
        .is_err());
    // Ownership is admin on the region and nothing else: no nodes inside it.
    assert!(forbidden(holder.mkdir(&library, "Season 1", |d| {
        crypto::sign_digest(&holder_key, d).unwrap()
    })));
    // A key with no grant on the region cannot publish for it.
    assert!(forbidden(other.commit_region_head(&library, 2, &hash, |d| {
        crypto::sign_digest(&other_key, d).unwrap()
    })));
    assert_eq!(region_head(dir.path(), &library).0, 1, "nothing above moved the head");
}
