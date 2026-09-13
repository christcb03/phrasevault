//! D145 — the drain's question over the wire: a holder confirms only the
//! bytes it serves now, judged by their last chunk read back by content hash.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use pvfs_client::drain::confirm_held;
use pvfs_core::acl::{self, Principal};
use pvfs_core::sync::{self, SWARM_CHUNK};
use pvfs_core::{crypto, identity, BindSpec, DrainCheck, Engine, HashPolicy, NodeSpec, ReplicaSource, TYPE_FOLDER};
use pvfsd::{serve, Daemon};

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

fn region(e: &mut Engine, label: &str, dir: &std::path::Path) -> String {
    let root = e.identity.root_node_id.clone();
    let r = folder(e, &root, label);
    e.region_mark_as(&r, "catalogue", None).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    e.bind_folder(
        &r,
        BindSpec {
            source_uri: format!("file://{}", dir.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&r), None, 0).unwrap();
    r
}

#[test]
fn a_holder_confirms_only_the_bytes_it_serves_now() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("library");
    let big: Vec<u8> = (0..(SWARM_CHUNK as usize + 1_000_000)).map(|i| (i % 251) as u8).collect();
    std::fs::create_dir_all(lib.join("Shows")).unwrap();
    std::fs::write(lib.join("Shows/big.mkv"), &big).unwrap();
    let h_big = blake3::hash(&big).to_hex().to_string();

    let (mut holder, mn) = Engine::init(tmp.path().join("holder").as_path()).unwrap();
    let rl = region(&mut holder, "Library", &lib);
    let me_key = identity::device_key(&identity::client_identity_mnemonic().unwrap(), "", 0).unwrap();
    let me_pub = crypto::pubkey_bytes(&me_key);
    holder.authorize_member(&mn, &me_pub).unwrap();
    let root = holder.identity.root_node_id.clone();
    holder.set_acl(&root, &Principal::Key(me_pub.clone()), acl::ACL_R).unwrap();

    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let daemon = Arc::new(Daemon::new(holder));
    {
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || {
            let _ = serve(listener, d);
        });
    }
    let src = ReplicaSource {
        transport: "socket".into(),
        target: sock.to_string_lossy().into_owned(),
        pin: String::new(),
        region: String::new(),
    };
    let srcs = std::slice::from_ref(&src);

    let (off, len, tail) = sync::tail_chunk(&lib.join("Shows/big.mkv"), big.len() as u64).unwrap();
    assert_eq!((off, len), (SWARM_CHUNK, 1_000_000));
    let check = DrainCheck {
        rel_path: "Shows/big.mkv".into(),
        region: rl,
        hash: h_big,
        size: big.len() as u64,
        tail_offset: off,
        tail_len: len,
        tail_hash: tail,
    };
    assert!(confirm_held(srcs, &check), "the holder serves the last chunk and it matches");

    let mut wrong = check.clone();
    wrong.tail_hash = [0u8; 32];
    assert!(!confirm_held(srcs, &wrong), "a last chunk that differs is a no");
    let mut ghost = check.clone();
    ghost.hash = "00".repeat(32);
    assert!(!confirm_held(srcs, &ghost), "bytes nobody holds are a no");
    assert!(!confirm_held(&[], &check), "nobody to ask is a no");

    // Changed in place after its scan, same size: the row still names the
    // hash, but the last chunk the holder serves is not ours.
    let mut changed = big.clone();
    *changed.last_mut().unwrap() ^= 0xff;
    std::fs::write(lib.join("Shows/big.mkv"), &changed).unwrap();
    assert!(!confirm_held(srcs, &check), "changed in place is a no");

    // And gone — what an arr's delete through the union looks like.
    std::fs::remove_file(lib.join("Shows/big.mkv")).unwrap();
    assert!(!confirm_held(srcs, &check), "deleted is a no");
}
