//! PVOS D220 — a holder serves a reader that was already reading a file from
//! the region's trash once the live copy has gone there (a Plex stream while
//! Sonarr upgrades the episode). Only when asked (`trashed`), only with read
//! on the region, only bytes whose sidecar names the hash at the sidecar's
//! size; a trash another process made a moment ago is found once the index is
//! two seconds old, and a purged file is gone.

use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::time::Duration;

use pvfs_client::{Client, ClientError};
use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, sync, BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn bytes(n: usize, salt: u64) -> Vec<u8> {
    (0..n as u64)
        .map(|i| (i.wrapping_add(salt).wrapping_mul(2_654_435_761).rotate_left(9) >> 3) as u8)
        .collect()
}

fn cat(c: &mut Client, hash: &str, off: u64, len: u64, trashed: bool) -> Result<Vec<u8>, ClientError> {
    let mut out = Vec::new();
    c.cat_hash_range_from(hash, off, len, trashed, &mut out).map(|_| out)
}

fn code<T: std::fmt::Debug>(r: Result<T, ClientError>) -> String {
    match r {
        Err(ClientError::Server { code, .. }) => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_trashed_file_is_served_to_a_reader_that_asks_and_to_nobody_else() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();
    let files = tmp.path().join("files");
    std::fs::create_dir_all(files.join("TV/Show")).unwrap();
    let a = bytes(3 * 1024 * 1024 + 5, 1);
    let b = bytes(1024 * 1024 + 7, 2);
    let (pa, pb) = (files.join("TV/Show/a.mkv"), files.join("TV/Show/b.mkv"));
    std::fs::write(&pa, &a).unwrap();
    std::fs::write(&pb, &b).unwrap();
    let h = |x: &[u8]| blake3::hash(x).to_hex().to_string();
    let (ha, hb) = (h(&a), h(&b));

    let (mut holder, mn) = Engine::init(tmp.path().join("holder").as_path()).unwrap();
    let root = holder.identity.root_node_id.clone();
    let lib = holder
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
    holder.region_mark_as(&lib, "catalogue", None).unwrap();
    holder
        .bind_folder(
            &lib,
            BindSpec {
                source_uri: format!("file://{}", files.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
    holder.scan_routed(Some(&lib), None, 0).unwrap();
    assert!(sync::manifest_sidecar_path(&pa).is_file(), "premise: the scan left a sidecar");
    let me = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me);
    let stranger = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let stranger_pub = crypto::pubkey_bytes(&stranger);
    holder.authorize_member(&mn, &me_pub).unwrap();
    holder.authorize_member(&mn, &stranger_pub).unwrap();
    holder.set_acl(&root, &Principal::Key(me_pub.clone()), acl::ACL_R).unwrap();
    let sock = tmp.path().join("holder.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(holder));
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });
    let mut c = Client::connect_signed(&sock, &me_pub, |d| crypto::sign_digest(&me, d).unwrap()).unwrap();
    let mut s = Client::connect_signed(&sock, &stranger_pub, |d| crypto::sign_digest(&stranger, d).unwrap()).unwrap();

    // ---- live: served either way
    assert_eq!(cat(&mut c, &ha, 0, 0, false).unwrap(), a);
    assert_eq!(cat(&mut c, &ha, 0, 0, true).unwrap(), a);

    // ---- the upgrade trashes it (another process, as `pvfs trash put` or
    // the routed delete does it: the file and its sidecar into the trash)
    let went = sync::move_to_trash_with_sidecar(&files, &pa).unwrap();
    assert!(went.starts_with(sync::trash_root(&files)));
    assert_eq!(code(cat(&mut c, &ha, 0, 0, false)), "not_found", "a reader that was not reading: gone (D219)");
    assert_eq!(cat(&mut c, &ha, 0, 0, true).unwrap(), a, "a reader that was reading: the trashed copy, whole");
    let mid = 1024 * 1024 + 3;
    assert_eq!(cat(&mut c, &ha, mid, 4096, true).unwrap(), a[mid as usize..mid as usize + 4096], "and by range");
    assert_eq!(code(cat(&mut s, &ha, 0, 0, true)), "forbidden", "no read on the region: refused, as live");
    assert_eq!(code(cat(&mut c, &"0".repeat(64), 0, 0, true)), "not_found", "nowhere: not found");

    // ---- a trash made a moment after the index was built is found once the
    // index is two seconds old
    sync::move_to_trash_with_sidecar(&files, &pb).unwrap();
    assert_eq!(code(cat(&mut c, &hb, 0, 0, true)), "not_found", "inside two seconds of the build: not yet");
    std::thread::sleep(Duration::from_millis(2_100));
    assert_eq!(cat(&mut c, &hb, 0, 0, true).unwrap(), b, "then the miss rebuilds and finds it");

    // ---- purged: gone for everyone
    std::fs::remove_file(&went).unwrap();
    std::thread::sleep(Duration::from_millis(2_100));
    assert_eq!(code(cat(&mut c, &ha, 0, 0, true)), "not_found", "a purged file is not served");
}
