//! PVOS D193 — a personal forest's genesis, signed by the person.
//!
//! Prepared from public keys, signed with the person's root and own device
//! key, committed by the hosting box only after a full verifying replay.
//! The box's key is a member with no grant; the person's identity key is an
//! admin member (it certifies their session keys).

use pvfs_core::acl::{Principal, ACL_A, ACL_R, ACL_W};
use pvfs_core::personal::{init_signed_genesis, prepare_personal_genesis, PersonalGenesis};
use pvfs_core::{crypto, identity, Engine, NodeSpec};

struct Person {
    root: identity::SigningKey,
    device: identity::SigningKey,
    ident: identity::SigningKey,
}

impl Person {
    fn new() -> Person {
        let mn = identity::generate_mnemonic().unwrap();
        Person {
            root: identity::root_key(&mn, "").unwrap(),
            device: identity::device_key(&mn, "", 0).unwrap(),
            ident: identity::identity_key(&mn, "", 0).unwrap(),
        }
    }

    fn genesis(&self, host: &identity::SigningKey) -> PersonalGenesis {
        PersonalGenesis {
            root_pub: crypto::pubkey_bytes(&self.root),
            owner_device_pub: crypto::pubkey_bytes(&self.device),
            identity_pub: crypto::pubkey_bytes(&self.ident),
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
    assert_eq!(prep.events.len(), 7);
    let forest_id = prep.forest_id.clone();
    let events = prep.sign(&person.root, &person.device).unwrap();
    let mut engine = init_signed_genesis(&data, events, host.clone()).unwrap();

    assert_eq!(engine.identity.forest_id, forest_id);
    assert_eq!(engine.certificates_bound().unwrap().as_deref(), Some("genesis"), "born bound");
    assert_eq!(engine.current_root().unwrap(), crypto::pubkey_bytes(&person.root));
    let root = engine.identity.root_node_id.clone();
    let rights = |k: &identity::SigningKey| engine.effective_rights(&Principal::Key(crypto::pubkey_bytes(k)), &root).unwrap();
    assert_eq!(rights(&person.ident), ACL_R | ACL_W | ACL_A, "the identity is an admin member");
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

    // the person's identity certifies a session key (what a sign-in does)
    let session = crypto::pubkey_bytes(&identity::generate_device_key());
    let mut p = engine.prepare_authorize_member(&crypto::pubkey_bytes(&person.ident), &session).unwrap().events.remove(0);
    p.event.set_author_sig(crypto::sign_digest(&person.ident, &p.digest).unwrap());
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
    // the owner-device events signed by someone else
    let events = prep.sign(&person.root, &identity::generate_device_key()).unwrap();
    assert!(init_signed_genesis(&data, events, host).is_err());
    assert!(!data.exists(), "nothing is left behind");
}

#[test]
fn the_box_opens_it_only_with_the_key_the_genesis_admits() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("people-carol");
    let person = Person::new();
    let host = identity::generate_device_key();
    let events = prepare_personal_genesis(&person.genesis(&host)).unwrap().sign(&person.root, &person.device).unwrap();
    assert!(init_signed_genesis(&data, events, identity::generate_device_key()).is_err());
    assert!(!data.exists());

    let mut same = person.genesis(&host);
    same.identity_pub = same.root_pub.clone();
    assert!(prepare_personal_genesis(&same).is_err(), "the four keys must differ");
}

/// The keys a browser derives from a phrase must be the ones PVFS derives:
/// these vectors are pinned in the web page's tests too.
#[test]
fn the_phrase_keys_the_page_must_derive() {
    let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let mn = identity::parse_mnemonic(words).unwrap();
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
