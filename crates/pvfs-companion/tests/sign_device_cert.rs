//! Integration (doc 14 §9 phase 2): the companion **root-signs** a
//! `DeviceAuthorized` that the engine prepared, and the engine commits it — the
//! phrase-free admit flow, end to end across the vault + signer + kernel.

use pvfs_companion::{
    ApprovalPolicy, Decision, KeyRole, KdfParams, Origin, RequestType, UnlockedSigner, Vault,
};
use pvfs_core::{crypto, identity, Engine};

// Fast KDF for the test vault.
fn fast() -> KdfParams {
    KdfParams {
        m_cost: 32,
        t_cost: 1,
        p_cost: 1,
    }
}

#[test]
fn companion_root_signs_device_authorized() {
    // A forest, owned by `owner_mn`.
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root_pub = crypto::pubkey_bytes(&identity::root_key(&owner_mn, "").unwrap());

    // Seal the owner's phrase in a companion vault, then unlock it into a signer.
    let vdir = tempfile::tempdir().unwrap();
    let vpath = vdir.path().join("vault.json");
    let phrase = owner_mn.to_string();
    Vault::create_with(&vpath, phrase.as_bytes(), b"pw", fast()).unwrap();
    let secret = Vault::open(&vpath).unwrap().unseal(b"pw").unwrap();
    let signer = UnlockedSigner::from_phrase(std::str::from_utf8(&secret).unwrap()).unwrap();

    // The signer's root key is the forest's identity root.
    assert_eq!(signer.pubkey(KeyRole::Root).unwrap(), root_pub);

    // A brand-new member key to admit.
    let member = crypto::pubkey_bytes(
        &identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap(),
    );
    assert!(!engine.authority_active(&member).unwrap());

    // The daemon prepares a root-authored DeviceAuthorized.
    let prep = engine.prepare_authorize_member(&root_pub, &member).unwrap();
    assert_eq!(prep.events.len(), 1);

    // Policy: a root device cert needs approval; an interactive companion approves.
    let policy = ApprovalPolicy {
        auto_root: true,
        ..Default::default()
    };
    assert_eq!(
        policy.decide(RequestType::RootDeviceCert, Origin::Local),
        Decision::Approve
    );
    // And a headless companion would NOT auto-approve a root event by default.
    assert_eq!(
        ApprovalPolicy::default().decide_headless(RequestType::RootDeviceCert, Origin::Local),
        Decision::Deny
    );

    // The companion signs the prepared digest with the root key; the daemon commits.
    let mut ev = prep.events.into_iter().next().unwrap();
    let sig = signer.sign(RequestType::RootDeviceCert, &ev.digest).unwrap();
    ev.event.set_author_sig(sig);
    engine.commit_member_write(vec![ev.event]).unwrap();

    // The member is now an authorized, active member of the forest.
    assert!(engine.authority_active(&member).unwrap());
    engine.close().unwrap();
}

/// Doc 14 §9 phase 3: the identity key is admitted as an owner
/// (`IDENTITY_DEVICE_INDEX`), grants a tag under its own stable authority
/// (doc 10 §9.1), and the root revokes a member — every op through the same
/// prepare → companion-sign → commit shape the CLI uses.
#[test]
fn companion_identity_key_tags_and_root_revokes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, owner_mn) = Engine::init(dir.path()).unwrap();
    let root_pub = crypto::pubkey_bytes(&identity::root_key(&owner_mn, "").unwrap());

    let vdir = tempfile::tempdir().unwrap();
    let vpath = vdir.path().join("vault.json");
    Vault::create_with(&vpath, owner_mn.to_string().as_bytes(), b"pw", fast()).unwrap();
    let secret = Vault::open(&vpath).unwrap().unseal(b"pw").unwrap();
    let signer = UnlockedSigner::from_phrase(std::str::from_utf8(&secret).unwrap()).unwrap();

    // Shared shape: prepare one event, companion-sign it, commit.
    let commit = |engine: &mut Engine, rt: RequestType, prep: pvfs_core::PreparedWrite| {
        let mut ev = prep.events.into_iter().next().unwrap();
        ev.event.set_author_sig(signer.sign(rt, &ev.digest).unwrap());
        engine.commit_member_write(vec![ev.event]).unwrap();
    };

    // Admit the identity key (doc 14 §1) as an owner, root-signed.
    let id_pub = signer.pubkey(KeyRole::Identity).unwrap();
    let prep = engine.prepare_authorize_identity(&root_pub, &id_pub).unwrap();
    commit(&mut engine, RequestType::RootDeviceCert, prep);
    assert!(engine.authority_active(&id_pub).unwrap());

    // Re-admitting the identity key is AlreadyExists — the cert landed.
    assert!(engine.prepare_authorize_identity(&root_pub, &id_pub).is_err());

    // Admit a member, then tag them under the identity key's authority.
    let member = crypto::pubkey_bytes(
        &identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap(),
    );
    let prep = engine.prepare_authorize_member(&root_pub, &member).unwrap();
    commit(&mut engine, RequestType::RootDeviceCert, prep);
    let prep = engine
        .prepare_set_member_tag(&id_pub, &member, "vip", true)
        .unwrap();
    commit(&mut engine, RequestType::IdentityTag, prep);
    assert_eq!(
        engine.member_tags(&member).unwrap(),
        vec![(id_pub.clone(), "vip".to_string())]
    );

    // The identity key removes its own grant.
    let prep = engine
        .prepare_set_member_tag(&id_pub, &member, "vip", false)
        .unwrap();
    commit(&mut engine, RequestType::IdentityTag, prep);
    assert!(engine.member_tags(&member).unwrap().is_empty());

    // Root revokes the member through the same shape.
    let prep = engine.prepare_revoke(&root_pub, &member).unwrap();
    commit(&mut engine, RequestType::RootDeviceCert, prep);
    assert!(!engine.authority_active(&member).unwrap());
    engine.close().unwrap();
}
