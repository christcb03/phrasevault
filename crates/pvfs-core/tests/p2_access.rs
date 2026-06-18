//! P2 access-control foundation (doc 06 §3–§4): member authorization + ACLs.

use pvfs_core::{acl, crypto, identity, Engine, NodeSpec, PvfsError, TYPE_FOLDER};

/// A well-formed compressed secp256k1 pubkey the forest has never seen.
fn foreign_pubkey() -> Vec<u8> {
    let k = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    crypto::pubkey_bytes(&k)
}

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

#[test]
fn authorize_member_guards_and_survives_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let member = foreign_pubkey();

    // malformed key → BadInput
    assert!(matches!(
        engine.authorize_member(&m, &[1u8, 2, 3]),
        Err(PvfsError::BadInput { .. })
    ));

    // wrong recovery phrase → Identity (only the identity root may authorize)
    let wrong = identity::generate_mnemonic().unwrap();
    assert!(matches!(
        engine.authorize_member(&wrong, &member),
        Err(PvfsError::Identity { .. })
    ));

    // happy path, then duplicate → AlreadyExists
    engine.authorize_member(&m, &member).unwrap();
    assert!(matches!(
        engine.authorize_member(&m, &member),
        Err(PvfsError::AlreadyExists { .. })
    ));
    engine.close().unwrap();

    // the grant is a root-signed log event: it survives a full projection rebuild
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    Engine::open(dir.path())
        .expect("authorized member survives rebuild")
        .close()
        .unwrap();
}

// doc 06 §4.2 — grant inheritance, the `any` wildcard, owner-always-full, rebuild
#[test]
fn acl_inheritance_wildcard_and_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = engine.add_node(&root, folder("media")).unwrap();
    let clip = engine.add_node(&media, folder("clip")).unwrap();
    let private = engine.add_node(&root, folder("private")).unwrap();

    let member = foreign_pubkey();
    engine.authorize_member(&m, &member).unwrap();
    let p = acl::Principal::Key(member.clone());

    // a bare member has no rights anywhere
    assert_eq!(engine.effective_rights(&p, &root).unwrap(), 0);

    // grant read on /media → inherited down to /media/clip, not up to root or sibling
    engine.set_acl(&media, &p, acl::ACL_R).unwrap();
    assert_eq!(engine.effective_rights(&p, &media).unwrap(), acl::ACL_R);
    assert_eq!(engine.effective_rights(&p, &clip).unwrap(), acl::ACL_R);
    assert_eq!(engine.effective_rights(&p, &root).unwrap(), 0);
    assert_eq!(engine.effective_rights(&p, &private).unwrap(), 0);

    // `any` write on root reaches every authorized member, everywhere (inherited down)
    engine.set_acl(&root, &acl::Principal::Any, acl::ACL_W).unwrap();
    assert_eq!(
        engine.effective_rights(&p, &clip).unwrap(),
        acl::ACL_R | acl::ACL_W
    );

    // the owner device is always full, with or without explicit grants
    let owner = acl::Principal::Key(engine.device_pubkey());
    assert_eq!(engine.effective_rights(&owner, &private).unwrap(), acl::ACL_RWA);

    // clearing the /media grant drops R there; the wildcard W remains
    engine.set_acl(&media, &p, 0).unwrap();
    assert_eq!(engine.effective_rights(&p, &clip).unwrap(), acl::ACL_W);
    assert!(engine.acl_entries(&media).unwrap().is_empty());

    // a re-grant shows up as a direct entry
    engine.set_acl(&media, &p, acl::ACL_R).unwrap();
    assert_eq!(engine.acl_entries(&media).unwrap().len(), 1);
    engine.close().unwrap();

    // ACLs are log events → survive a full rebuild
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    assert_eq!(
        engine.effective_rights(&p, &clip).unwrap(),
        acl::ACL_R | acl::ACL_W
    );
    engine.close().unwrap();
}

// doc 06 §4.2 / doc 07 §10 — enforcement primitives the daemon will call
#[test]
fn can_and_readable_children() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let public = engine.add_node(&root, folder("public")).unwrap();
    let _secret = engine.add_node(&root, folder("secret")).unwrap();

    let member = foreign_pubkey();
    engine.authorize_member(&m, &member).unwrap();
    let p = acl::Principal::Key(member);
    engine.set_acl(&public, &p, acl::ACL_R).unwrap(); // read on `public` only

    assert!(engine.can(&p, &public, acl::ACL_R).unwrap());
    assert!(!engine.can(&p, &_secret, acl::ACL_R).unwrap());
    assert!(!engine.can(&p, &public, acl::ACL_W).unwrap());

    let visible: Vec<String> = engine
        .readable_children(&p, &root)
        .unwrap()
        .into_iter()
        .map(|c| c.node.id)
        .collect();
    assert_eq!(visible, vec![public], "member sees only the granted child");

    // the owner device sees every child
    let owner = acl::Principal::Key(engine.device_pubkey());
    assert_eq!(engine.readable_children(&owner, &root).unwrap().len(), 2);
    engine.close().unwrap();
}

// doc 07 §5 — two-phase member write: prepare (daemon) → member signs → commit
#[test]
fn member_write_two_phase() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let dropbox = engine.add_node(&root, folder("dropbox")).unwrap();

    let member_key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let member_pub = crypto::pubkey_bytes(&member_key);
    engine.authorize_member(&owner_mn, &member_pub).unwrap();
    engine
        .set_acl(
            &dropbox,
            &acl::Principal::Key(member_pub.clone()),
            acl::ACL_R | acl::ACL_W,
        )
        .unwrap();

    // no write on root → prepare is refused
    assert!(matches!(
        engine.prepare_add_node(&member_pub, &root, folder("nope")),
        Err(PvfsError::Forbidden { .. })
    ));

    // prepare under dropbox (has w) → the member signs each digest → commit
    let prep = engine
        .prepare_add_node(&member_pub, &dropbox, folder("hello"))
        .unwrap();
    let signed: Vec<_> = prep
        .events
        .into_iter()
        .map(|pe| {
            let mut ev = pe.event;
            ev.set_author_sig(crypto::sign_digest(&member_key, &pe.digest).unwrap());
            ev
        })
        .collect();
    engine.commit_member_write(signed).unwrap();

    // the new node exists under dropbox and is authored by the member, not the owner
    let kids = engine.children(&dropbox).unwrap();
    let hello = kids
        .iter()
        .find(|c| c.node.label == "hello")
        .expect("member created the node");
    assert_eq!(hello.node.author, member_pub);
    let hello_id = hello.node.id.clone();
    engine.close().unwrap();

    // the member write replays through a full rebuild (member had w when created)
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    assert!(engine.node(&hello_id).unwrap().is_some());
    engine.close().unwrap();
}

// doc 07 §4 — the three tiers: `public` reaches everyone; `any` only members
#[test]
fn acl_public_vs_any_tiers() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, m) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let shared = engine.add_node(&root, folder("shared")).unwrap();
    let members_only = engine.add_node(&root, folder("members-only")).unwrap();

    let member = foreign_pubkey();
    engine.authorize_member(&m, &member).unwrap();
    let memberp = acl::Principal::Key(member);
    let stranger = acl::Principal::Key(foreign_pubkey()); // never authorized

    // `public` read on `shared` reaches everyone — even an unauthorized/unknown key
    engine.set_acl(&shared, &acl::Principal::Public, acl::ACL_R).unwrap();
    assert!(engine.can(&acl::Principal::Public, &shared, acl::ACL_R).unwrap());
    assert!(engine.can(&memberp, &shared, acl::ACL_R).unwrap());
    assert!(engine.can(&stranger, &shared, acl::ACL_R).unwrap());
    assert!(!engine.can(&acl::Principal::Public, &root, acl::ACL_R).unwrap());

    // `any` read on `members-only` reaches authorized members only
    engine
        .set_acl(&members_only, &acl::Principal::Any, acl::ACL_R)
        .unwrap();
    assert!(engine.can(&memberp, &members_only, acl::ACL_R).unwrap());
    assert!(!engine.can(&acl::Principal::Public, &members_only, acl::ACL_R).unwrap());
    assert!(
        !engine.can(&stranger, &members_only, acl::ACL_R).unwrap(),
        "an unauthorized key is not a member"
    );
    engine.close().unwrap();
}
