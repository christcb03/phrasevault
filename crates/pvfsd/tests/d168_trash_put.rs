//! PVOS D168 — `pvfs trash put`'s list: `trash_each` sends D169's `TrashPath`
//! for ONE region's copy per item, over one connection per box, and every
//! item is its own answer. Two regions hold DIFFERENT bytes at the same path
//! (a same-path conflict, the duplicate cleanup's case): trashing one
//! region's copy leaves the other; a changed file, a region nobody holds,
//! missing write rights and a copy already gone are that item's answer and
//! the list goes on.

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;

use pvfs_core::acl::{self, Principal};
use pvfs_core::{crypto, identity, sync, BindSpec, Engine, HashPolicy, NodeSpec, ReplicaSource, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

fn h(b: &[u8]) -> String {
    blake3::hash(b).to_hex().to_string()
}

fn region_over(owner: &mut Engine, label: &str, files: &Path) -> String {
    let root = owner.identity.root_node_id.clone();
    let node = owner
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: label.into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    owner.region_mark_as(&node, "catalogue", None).unwrap();
    owner
        .bind_folder(
            &node,
            BindSpec {
                source_uri: format!("file://{}", files.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
    owner.scan_routed(Some(&node), None, 0).unwrap();
    node
}

#[test]
fn one_regions_copy_goes_and_a_list_goes_on_past_refusals() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let dir = tempfile::tempdir().unwrap();
    let nas = tempfile::tempdir().unwrap();
    let mb = tempfile::tempdir().unwrap();
    let ro = tempfile::tempdir().unwrap();
    for (root, files) in [
        (nas.path(), &[("Shows/S01/e01.mkv", "nas 1080p"), ("Shows/S01/e02.mkv", "nas e02"), ("Shows/S01/e03.mkv", "nas e03")][..]),
        (mb.path(), &[("Shows/S01/e01.mkv", "mediabox SD"), ("Shows/S01/e04.mkv", "mediabox e04")][..]),
        (ro.path(), &[("Shows/S01/e05.mkv", "read-only e05")][..]),
    ] {
        for (p, body) in files {
            std::fs::create_dir_all(root.join(p).parent().unwrap()).unwrap();
            std::fs::write(root.join(p), body).unwrap();
        }
    }

    let (mut owner, mn) = Engine::init(dir.path()).unwrap();
    let lib_nas = region_over(&mut owner, "NAS", nas.path());
    let lib_mb = region_over(&mut owner, "mediabox", mb.path());
    let lib_ro = region_over(&mut owner, "read only", ro.path());
    // What `trash_each` dials as: this box's client identity — write rights
    // on two regions, only read on the third (default deny).
    let me_key = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me_key);
    owner.authorize_member(&mn, &me_pub).unwrap();
    for (r, rights) in [(&lib_nas, acl::ACL_R | acl::ACL_W), (&lib_mb, acl::ACL_R | acl::ACL_W), (&lib_ro, acl::ACL_R)] {
        owner.set_acl(r, &Principal::Key(me_pub.clone()), rights).unwrap();
    }

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(owner));
    std::thread::spawn(move || {
        let _ = serve(listener, daemon);
    });
    let here = ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    };
    // A box that is not there first: it is skipped, every item.
    let nobody = ReplicaSource {
        target: sockdir.path().join("nobody.sock").to_string_lossy().into_owned(),
        ..here.clone()
    };
    let sources = [nobody, here];

    let item = |r: &str, p: &str, body: &str| (r.to_string(), p.to_string(), h(body.as_bytes()));
    let items = vec![
        // The same path in two regions, different bytes: only mediabox's goes.
        item(&lib_mb, "Shows/S01/e01.mkv", "mediabox SD"),
        // Not the file the plan saw: refused, nothing moves.
        item(&lib_nas, "Shows/S01/e02.mkv", "something else"),
        // A region no box has.
        ("cd".repeat(32), "Shows/S01/e03.mkv".into(), h(b"nas e03")),
        // Read rights are not leave to empty a region.
        item(&lib_ro, "Shows/S01/e05.mkv", "read-only e05"),
        // After all of that, the list is still going.
        item(&lib_nas, "Shows/S01/e03.mkv", "nas e03"),
        // Asked twice: the second time it is already gone — not an error.
        item(&lib_mb, "Shows/S01/e01.mkv", "mediabox SD"),
    ];
    let got = pvfs_client::hash_cache::trash_each(&sources, &items);
    assert_eq!(got.len(), items.len());
    assert_eq!(got[0], Ok(true), "mediabox's copy of e01");
    assert!(matches!(&got[1], Err(e) if e.contains("conflict")), "{:?}", got[1]);
    // A region no box has: a box with no rights reaching that node says
    // `forbidden` before it could say `not_found` — either way that item's
    // own refusal (in the fleet every box has every region's node).
    assert!(got[2].is_err(), "{:?}", got[2]);
    assert!(matches!(&got[3], Err(e) if e.contains("forbidden")), "{:?}", got[3]);
    assert_eq!(got[4], Ok(true), "the list went on past three refusals");
    assert_eq!(got[5], Ok(false), "already gone");

    // The disks agree: mediabox's e01 in its trash, the NAS's e01 — the
    // same path, the copy being kept — untouched; the refused ones in place.
    assert!(!mb.path().join("Shows/S01/e01.mkv").exists());
    assert_eq!(std::fs::read_to_string(nas.path().join("Shows/S01/e01.mkv")).unwrap(), "nas 1080p");
    assert!(nas.path().join("Shows/S01/e02.mkv").is_file());
    assert!(ro.path().join("Shows/S01/e05.mkv").is_file());
    assert!(!nas.path().join("Shows/S01/e03.mkv").exists());
    let trashed = |root: &Path| -> Vec<String> { sync::list_trash(root).into_iter().map(|t| t.rel_path).collect() };
    assert_eq!(trashed(mb.path()), vec!["Shows/S01/e01.mkv"]);
    assert_eq!(trashed(nas.path()), vec!["Shows/S01/e03.mkv"]);
    assert!(trashed(ro.path()).is_empty());
}
