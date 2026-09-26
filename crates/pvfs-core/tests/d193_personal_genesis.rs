//! PVOS D193 — a personal forest's genesis, signed by the person.
//!
//! Prepared from public keys, signed with the person's root and device keys,
//! committed by the hosting box only after a full verifying replay. The box's
//! key is a member with no grant; the person's device key (`1'/0'`) is the
//! owner device (it certifies their session keys).

use pvfs_core::acl::{Principal, ACL_A, ACL_R, ACL_W};
use pvfs_core::personal::{
    init_signed_genesis, prepare_personal_genesis, prepare_personal_genesis_with, session_cert_events, GenesisParams,
    GenesisSigner, PersonalGenesis, SessionCert,
};
use pvfs_core::event::{self, Event};
use pvfs_core::{crypto, identity, Engine, NodeSpec};

struct Person {
    root: identity::SigningKey,
    owner: identity::SigningKey,
}

impl Person {
    fn new() -> Person {
        let mn = identity::generate_mnemonic().unwrap();
        Person {
            root: identity::root_key(&mn, "").unwrap(),
            owner: identity::device_key(&mn, "", 0).unwrap(),
        }
    }

    fn genesis(&self, host: &identity::SigningKey) -> PersonalGenesis {
        PersonalGenesis {
            root_pub: crypto::pubkey_bytes(&self.root),
            owner_pub: crypto::pubkey_bytes(&self.owner),
            host_pub: crypto::pubkey_bytes(host),
        }
    }
}

#[test]
fn a_personal_forest_is_the_persons_and_its_host_holds_no_grant() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("people-alice");
    let person = Person::new();
    let host = identity::generate_device_key();
    let prep = prepare_personal_genesis(&person.genesis(&host)).unwrap();
    assert_eq!(prep.events.len(), 5);
    let forest_id = prep.params.forest_id.clone();
    let events = prep.sign(&person.root, &person.owner).unwrap();
    let mut engine = init_signed_genesis(&data, events, host.clone()).unwrap();

    assert_eq!(engine.identity.forest_id, forest_id);
    assert_eq!(engine.certificates_bound().unwrap().as_deref(), Some("genesis"), "born bound");
    assert_eq!(engine.current_root().unwrap(), crypto::pubkey_bytes(&person.root));
    let root = engine.identity.root_node_id.clone();
    let rights = |k: &identity::SigningKey| engine.effective_rights(&Principal::Key(crypto::pubkey_bytes(k)), &root).unwrap();
    assert_eq!(rights(&person.owner), ACL_R | ACL_W | ACL_A, "the device key is the owner device");
    assert_eq!(rights(&host), 0, "the host holds no grant");

    // the host cannot write on its own, nor admit anyone
    let spec = NodeSpec {
        node_type: "folder".into(),
        label: "mine".into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    };
    assert!(engine.add_node(&root, spec).is_err(), "the host's key writes nothing");
    let stranger = crypto::pubkey_bytes(&identity::generate_device_key());
    assert!(engine.prepare_authorize_member(&crypto::pubkey_bytes(&host), &stranger).is_err());

    // the person's device key certifies a session key (what a sign-in does)
    let session = crypto::pubkey_bytes(&identity::generate_device_key());
    let mut p = engine.prepare_authorize_member(&crypto::pubkey_bytes(&person.owner), &session).unwrap().events.remove(0);
    p.event.set_author_sig(crypto::sign_digest(&person.owner, &p.digest).unwrap());
    engine.commit_member_write(vec![p.event]).unwrap();
    assert!(engine.authority_active(&session).unwrap());
    engine.close().unwrap();

    Engine::open(&data).expect("the personal forest replays").close().unwrap();
}

#[test]
fn a_genesis_that_does_not_verify_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("people-bob");
    let person = Person::new();
    let host = identity::generate_device_key();
    let prep = prepare_personal_genesis(&person.genesis(&host)).unwrap();
    // the owner's events signed by someone else
    let events = prep.clone().sign(&person.root, &identity::generate_device_key()).unwrap();
    assert!(init_signed_genesis(&data, events, host.clone()).is_err());
    assert!(!data.exists(), "nothing is left behind");

    // a genesis signed in the unbound (v1) form: a personal forest is born bound
    let mut events = prep.sign(&person.root, &person.owner).unwrap();
    if let Event::ForestCreated { instance_id, forest_id, root_node_id, created_at, author, sig } = &mut events[0] {
        let v1 = event::msg_forest_created(instance_id, forest_id, root_node_id, *created_at, author, false);
        *sig = crypto::sign_digest(&person.root, &v1).unwrap();
    }
    let Err(err) = init_signed_genesis(&data, events, host).map(|_| ()) else { panic!("an unbound genesis was kept") };
    let err = err.to_string();
    assert!(err.contains("born bound"), "{err}");
    assert!(!data.exists());
}

#[test]
fn the_box_opens_it_only_with_the_key_the_genesis_admits() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("people-carol");
    let person = Person::new();
    let host = identity::generate_device_key();
    let events = prepare_personal_genesis(&person.genesis(&host)).unwrap().sign(&person.root, &person.owner).unwrap();
    assert!(init_signed_genesis(&data, events, identity::generate_device_key()).is_err());
    assert!(!data.exists());

    let mut same = person.genesis(&host);
    same.owner_pub = same.root_pub.clone();
    assert!(prepare_personal_genesis(&same).is_err(), "the keys must differ");
}

/// BIP39's all-zero 256-bit vector.
const VECTOR: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// The keys a browser derives from a phrase must be the ones PVFS derives:
/// these vectors are pinned in the web page's tests too.
#[test]
fn the_phrase_keys_the_page_must_derive() {
    let mn = identity::parse_mnemonic(VECTOR).unwrap();
    let hex = |k: identity::SigningKey| hex::encode(crypto::pubkey_bytes(&k));
    let got = [
        ("root 0'", hex(identity::root_key(&mn, "").unwrap())),
        ("device 1'/0'", hex(identity::device_key(&mn, "", 0).unwrap())),
        ("encryption 2'/0'", hex(identity::encryption_key(&mn, "", 0).unwrap())),
        ("identity 3'/0'", hex(identity::identity_key(&mn, "", 0).unwrap())),
    ];
    let pinned = [
        ("root 0'", "036242fd83e40688fc2c61fa05061edc98fef9bf2e4c85c28718b9d5f4f6acd2ac"),
        ("device 1'/0'", "02c3a30e05b8c44bf16f0fcec80f481954acb45984d6ff6d6b0766385362092656"),
        ("encryption 2'/0'", "03d02843b4ffdfe3ae8a18feb3a9a2e6a4d5cc39150f2e8d9990da1b281355d744"),
        ("identity 3'/0'", "036435e78bcc147f4c92e0db70d4107d0c5bf04b169cf1b3d339212088df21a544"),
    ];
    for ((what, key), (_, want)) in got.iter().zip(pinned) {
        assert_eq!(key, want, "{what}");
    }
}

/// The genesis digests from fixed inputs — pinned in the web page's tests:
/// the page builds them itself from parameters it chose and the host's key
/// (so no server can slip itself in as the owner device, or aim a
/// certificate at another forest), and the box rebuilds the same events to
/// attach its signatures.
#[test]
fn the_genesis_digests_the_page_must_recompute() {
    use pvfs_core::{acl, link, node};
    let root = hex::decode("036242fd83e40688fc2c61fa05061edc98fef9bf2e4c85c28718b9d5f4f6acd2ac").unwrap();
    // the owner: the vector's device key 1'/0'
    let owner = hex::decode("02c3a30e05b8c44bf16f0fcec80f481954acb45984d6ff6d6b0766385362092656").unwrap();
    // any other key will do as the host's: the vector's encryption key
    let host = hex::decode("03d02843b4ffdfe3ae8a18feb3a9a2e6a4d5cc39150f2e8d9990da1b281355d744").unwrap();
    let (instance, forest, t, nonce) = ("pvfs-00000001", "00000000-0000-4000-8000-000000000001", 1_700_000_000_000u64, 0x0123_4567_89ab_cdefu64);
    let node_id = hex::encode(node::compute_id_digest(node::TYPE_FOLDER, "root", node::VISIBILITY_PUBLIC, &[], false, nonce, t, &owner));
    let got = [
        ("root node", node_id.clone()),
        ("root link", hex::encode(link::compute_id_digest(None, &node_id, link::LINK_CONTAINS, 0))),
        ("forest created v2", hex::encode(event::msg_forest_created(instance, forest, &node_id, t, &root, true))),
        ("device key as owner device", hex::encode(event::msg_device_authorized(Some(forest), &owner, 0, t, &root))),
        ("host as member", hex::encode(event::msg_device_authorized(Some(forest), &host, acl::MEMBER_DEVICE_INDEX, t, &root))),
    ];
    let pinned = [
        "ab6204fd70bb60e2dbaa651ac02bb755289ac2673fefb49e30c8eef6c68835fb",
        "11aef9525fd2eba6c68b502be50e47cfe6e7ee1a1f66d2a312bb969b6b4dfb16",
        "502b11561516cb8e4fbfd885707fdd3520294246e988785e8c2f99036df87265",
        "6ce5ea738991800e65aaf6086b42976d7b88e1767b191290982e0b848beb06e6",
        "c00c8a1d1898f119bdb3ef08fde6b26033a7e4f6777e459a1b61fd918c8b5e8b",
    ];
    for ((what, d), want) in got.iter().zip(pinned) {
        assert_eq!(d, want, "{what}");
    }

    // ... and they are exactly what the box prepares from those parameters,
    // in log order, each with its signer.
    let params = GenesisParams { forest_id: forest.into(), instance_id: instance.into(), created_at: t, root_nonce: nonce };
    let g = PersonalGenesis { root_pub: root, owner_pub: owner, host_pub: host };
    let prep = prepare_personal_genesis_with(&g, params).unwrap();
    let order = [(2, GenesisSigner::Root), (3, GenesisSigner::Root), (0, GenesisSigner::Owner), (1, GenesisSigner::Owner), (4, GenesisSigner::Root)];
    assert_eq!(prep.events.len(), order.len());
    for (p, (i, signer)) in prep.events.iter().zip(order) {
        assert_eq!(hex::encode(p.digest), pinned[i], "{}", got[i].0);
        assert_eq!(p.signer, signer, "{}", got[i].0);
    }

    // The signatures the vector phrase's keys make over them (RFC 6979 is
    // deterministic, so the page's must be these exact bytes) — and they
    // make a personal forest the box keeps.
    let mn = identity::parse_mnemonic(VECTOR).unwrap();
    let (root_key, owner_key) = (identity::root_key(&mn, "").unwrap(), identity::device_key(&mn, "", 0).unwrap());
    let sigs: Vec<String> = prep
        .events
        .iter()
        .map(|p| {
            let key = if p.signer == GenesisSigner::Root { &root_key } else { &owner_key };
            hex::encode(crypto::sign_digest(key, &p.digest).unwrap())
        })
        .collect();
    let pinned_sigs = [
        "0f3698e75bf64a229156fb4105f67f73ad9765b07ff0c70696482034d190d86a4f104ac0cca0584cb200a2eed563b83c03bd92b570288fee1b8e81f38af64c2c",
        "7a0307541172811629b996f4ae19a34b24808c93cf834ff9bc2ade3944300e3f4d0fdc6d6057841891e25f0a4fd9c093a7f1d717090fbf2130eeb9fe2413e138",
        "304781f4eb88dd60545da5ffe5d834b03d2024682d788033382217009996aeda17b708084410631eb19a0594538b3d54c8df6e82e27ed88a36fb5a9bc3a248f3",
        "1a88a42be38fe884d335f7e15f4f5ab6493b25f490f15030c4815a4e9ea2049575c385880da900166c8a4d6b4d0dfb884d0f32769cf17ea1cde3819bd8a4d874",
        "8ce8dbce16cc44029acfd0a4fd500f2adf019b8dd84936be4f7ef7783e6fb93033043ad34c1a7a1c3a72df4cb1fc72657cef703a1bf33665a5da1d59d1db661a",
    ];
    assert_eq!(sigs, pinned_sigs, "the genesis signatures");
    let dir = tempfile::tempdir().unwrap();
    let events = prep.attach(sigs.iter().map(|s| hex::decode(s).unwrap()).collect()).unwrap();
    let host_key = identity::encryption_key(&mn, "", 0).unwrap();
    let engine = init_signed_genesis(&dir.path().join("vector"), events, host_key).expect("the vector genesis replays");
    assert_eq!(engine.identity.forest_id, forest);
    engine.close().unwrap();
}

/// The signer's parameters name sockets and directories on the box: only
/// the one canonical form is accepted.
#[test]
fn genesis_parameters_are_checked() {
    let person = Person::new();
    let host = identity::generate_device_key();
    let ok = GenesisParams::fresh();
    assert!(prepare_personal_genesis_with(&person.genesis(&host), ok.clone()).is_ok());
    let with = |f: &dyn Fn(&mut GenesisParams)| {
        let mut p = ok.clone();
        f(&mut p);
        prepare_personal_genesis_with(&person.genesis(&host), p)
    };
    assert!(with(&|p| p.forest_id = "../../run/pvfs/x".into()).is_err(), "a path");
    assert!(with(&|p| p.forest_id = "0A0B0C0D-0000-4000-8000-00000000000E".into()).is_err(), "uppercase");
    assert!(with(&|p| p.forest_id = "0a0b0c0d-0000-4000-8000-00000000000e".into()).is_ok(), "its lowercase form");
    assert!(with(&|p| p.forest_id = p.forest_id.replace('-', "")).is_err(), "unhyphenated");
    assert!(with(&|p| p.forest_id = "00000000-0000-1000-8000-000000000001".into()).is_err(), "not random (v1)");
    assert!(with(&|p| p.instance_id = "pvfs-0000000G".into()).is_err(), "instance not hex");
    assert!(with(&|p| p.instance_id = "pvfs-000000001".into()).is_err(), "instance too long");
    assert!(with(&|p| p.created_at = 0).is_err(), "no time");
}

/// A session certificate from fixed inputs — the digests and the owner key's
/// signatures the web page's tests pin too (it builds these itself at every
/// sign-in, from the forest its own key bound at join).
#[test]
fn the_session_certificate_the_page_must_build() {
    let mn = identity::parse_mnemonic(VECTOR).unwrap();
    let owner = identity::device_key(&mn, "", 0).unwrap();
    let cert = SessionCert {
        forest_id: "00000000-0000-4000-8000-000000000001".into(),
        root_node_id: "ab6204fd70bb60e2dbaa651ac02bb755289ac2673fefb49e30c8eef6c68835fb".into(),
        owner_pub: crypto::pubkey_bytes(&owner),
        // any other key will do as the session's: the vector's encryption key
        session_pub: hex::decode("03d02843b4ffdfe3ae8a18feb3a9a2e6a4d5cc39150f2e8d9990da1b281355d744").unwrap(),
        at: 1_700_000_001_000,
        expires_at: 1_700_000_001_000 + 7 * 24 * 3_600_000,
    };
    let prepared = session_cert_events(&cert).unwrap();
    let got: Vec<(String, String)> = prepared
        .iter()
        .map(|p| (hex::encode(p.digest), hex::encode(crypto::sign_digest(&owner, &p.digest).unwrap())))
        .collect();
    let pinned = [
        ("2fe0a5eeaa9bdbce2a666d9078b1767a5967b006362873d9352241c47ca633d4", "ffb1e8a8ff1ec93fbca584d44d4e67cbcaf428799ed386ea9eb2907726c80f6433ba94ee226746297ff476f591308cbe5747a7efcbab13a7e7f3789baa36e022"), // the session key as a member
        ("5863431a5c11ceaa98726ad259c54d6c8c2d9b5aea4026f797252d314e18c7db", "2a9b97096a66183bc935443f9e2916137eed55c92e04778e114a7a68316874f923dede8491d8602b26edd6902dc363e535cdf133fc0080c204ec09b63c07cb23"), // rw on the root until expiry
    ];
    for ((d, sig), (wd, ws)) in got.iter().zip(pinned) {
        assert_eq!((d.as_str(), sig.as_str()), (wd, ws));
    }

    let mut bad = cert.clone();
    bad.expires_at = bad.at;
    assert!(session_cert_events(&bad).is_err(), "a grant that never lives");
    let mut bad = cert.clone();
    bad.session_pub = bad.owner_pub.clone();
    assert!(session_cert_events(&bad).is_err(), "the owner as its own session");
}
