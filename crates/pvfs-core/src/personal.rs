//! PVOS D193 — a PERSONAL forest's genesis, signed by the person.
//!
//! A person's forest is rooted in their own phrase and hosted by a box that
//! must not hold authority in it by position. So the genesis is prepared
//! from public keys alone and signed where the person's keys are (their
//! browser, or their companion):
//!
//! 1. `ForestCreated` — root-signed, v2: born bound (D192);
//! 2. their IDENTITY key (`3'/0'` of their phrase) as the forest's owner
//!    device — the key that signs them in and certifies their sessions,
//!    which a browser and a companion both hold;
//! 3. the root folder and 4. its link — by that identity;
//! 5. the hosting box's key as a member with NO grant: it serves the forest
//!    and commits what the person signed; it can grant, revoke or delete
//!    nothing on its own.
//!
//! [`init_signed_genesis`] writes the signed events and opens the forest,
//! which REPLAYS them — every signature and authority checked as any
//! follower would — before it is kept.

use std::path::Path;

use rand::RngCore;

use crate::acl::MEMBER_DEVICE_INDEX;
use crate::crypto;
use crate::engine::{self, Engine};
use crate::error::{PvfsError, Result};
use crate::event::{self, Event};
use crate::identity::{DeviceKeyCache, SigningKey};
use crate::link::{self, Link, LINK_CONTAINS};
use crate::log_store;
use crate::node::{self, Node};
use crate::orderkey::OrderKey;
use crate::projection;

/// The public keys a personal forest is made from.
#[derive(Clone, Debug)]
pub struct PersonalGenesis {
    /// The person's root (`0'`): roots the forest.
    pub root_pub: Vec<u8>,
    /// The person's identity (`3'/0'`): the forest's owner device.
    pub identity_pub: Vec<u8>,
    /// The hosting box's key: a member with no grant.
    pub host_pub: Vec<u8>,
}

/// Which of the person's keys signs a prepared event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisSigner {
    Root,
    Identity,
}

#[derive(Clone, Debug)]
pub struct PreparedGenesisEvent {
    pub signer: GenesisSigner,
    pub digest: [u8; 32],
    pub event: Event,
}

/// The unsigned genesis, in log order.
#[derive(Clone, Debug)]
pub struct PreparedGenesis {
    pub forest_id: String,
    pub instance_id: String,
    pub events: Vec<PreparedGenesisEvent>,
}

impl PreparedGenesis {
    /// Attach one signature per event, in order (a signer elsewhere — the
    /// person's browser — returns them that way).
    pub fn attach(self, sigs: Vec<Vec<u8>>) -> Result<Vec<Event>> {
        if sigs.len() != self.events.len() {
            return Err(PvfsError::BadInput {
                field: "genesis".into(),
                reason: format!("{} signatures for {} events", sigs.len(), self.events.len()),
            });
        }
        Ok(self.events.into_iter().zip(sigs).map(|(p, sig)| with_sig(p.event, sig)).collect())
    }

    /// Sign every event here, with the person's two keys (tests; a tool
    /// holding the phrase).
    pub fn sign(self, root: &SigningKey, identity: &SigningKey) -> Result<Vec<Event>> {
        let sigs = self
            .events
            .iter()
            .map(|p| match p.signer {
                GenesisSigner::Root => crypto::sign_digest(root, &p.digest),
                GenesisSigner::Identity => crypto::sign_digest(identity, &p.digest),
            })
            .collect::<Result<Vec<_>>>()?;
        self.attach(sigs)
    }
}

fn with_sig(mut ev: Event, sig: Vec<u8>) -> Event {
    match &mut ev {
        Event::ForestCreated { sig: s, .. } => *s = sig,
        _ => ev.set_author_sig(sig),
    }
    ev
}

/// The unsigned genesis of a personal forest (see the module docs).
pub fn prepare_personal_genesis(g: &PersonalGenesis) -> Result<PreparedGenesis> {
    let keys = [&g.root_pub, &g.identity_pub, &g.host_pub];
    for k in keys {
        crypto::validate_pubkey(k)?;
    }
    for (i, a) in keys.iter().enumerate() {
        if keys[..i].contains(a) {
            return Err(PvfsError::BadInput {
                field: "genesis".into(),
                reason: "the root, identity and host keys must all differ".into(),
            });
        }
    }
    let mut b = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut b);
    let instance_id = format!("pvfs-{}", hex::encode(b));
    let forest_id = uuid::Uuid::new_v4().to_string();
    let t = engine::now_ms();
    let f = Some(forest_id.as_str());
    let (root, device) = (g.root_pub.clone(), g.identity_pub.clone());

    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let creation_nonce = u64::from_le_bytes(nonce);
    let payload = node::folder_payload();
    let root_digest = node::compute_id_digest(
        node::TYPE_FOLDER,
        "root",
        node::VISIBILITY_PUBLIC,
        &payload,
        false,
        creation_nonce,
        t,
        &device,
    );
    let root_node = Node {
        id: hex::encode(root_digest),
        node_type: node::TYPE_FOLDER.into(),
        label: "root".into(),
        visibility: node::VISIBILITY_PUBLIC.into(),
        payload,
        is_temp: false,
        creation_nonce,
        created_at: t,
        author: device.clone(),
        sig: Vec::new(),
    };
    let link_digest = link::compute_id_digest(None, &root_node.id, LINK_CONTAINS, 0);
    let root_link = Link {
        id: hex::encode(link_digest),
        parent_id: None,
        child_id: root_node.id.clone(),
        link_type: LINK_CONTAINS.into(),
        link_nonce: 0,
        order_key: OrderKey::middle().as_str().into(),
        created_at: t,
        author: device.clone(),
        sig: Vec::new(),
        removed_at: None,
        superseded_by: None,
        suspended_at: None,
    };
    let root_node_id = root_node.id.clone();
    let member = |key: &[u8]| PreparedGenesisEvent {
        signer: GenesisSigner::Root,
        digest: event::msg_device_authorized(f, key, MEMBER_DEVICE_INDEX, t, &root),
        event: Event::DeviceAuthorized {
            device_pubkey: key.to_vec(),
            device_index: MEMBER_DEVICE_INDEX,
            authorized_at: t,
            author: root.clone(),
            sig: Vec::new(),
        },
    };
    let events = vec![
        PreparedGenesisEvent {
            signer: GenesisSigner::Root,
            digest: event::msg_forest_created(&instance_id, &forest_id, &root_node_id, t, &root, true),
            event: Event::ForestCreated {
                instance_id: instance_id.clone(),
                forest_id: forest_id.clone(),
                root_node_id: root_node_id.clone(),
                created_at: t,
                author: root.clone(),
                sig: Vec::new(),
            },
        },
        PreparedGenesisEvent {
            signer: GenesisSigner::Root,
            digest: event::msg_device_authorized(f, &device, 0, t, &root),
            event: Event::DeviceAuthorized {
                device_pubkey: device.clone(),
                device_index: 0,
                authorized_at: t,
                author: root.clone(),
                sig: Vec::new(),
            },
        },
        PreparedGenesisEvent { signer: GenesisSigner::Identity, digest: root_digest, event: Event::NodeCreated(root_node) },
        PreparedGenesisEvent { signer: GenesisSigner::Identity, digest: link_digest, event: Event::LinkCreated(root_link) },
        member(&g.host_pub),
    ];
    Ok(PreparedGenesis { forest_id, instance_id, events })
}

/// Write a signed personal genesis at `data_dir` and open the forest, with
/// `host_key` (a member the genesis admits) as this box's device. The open
/// replays every event — signatures and authority, as a follower would —
/// and a genesis that does not hold leaves nothing behind.
pub fn init_signed_genesis(data_dir: &Path, events: Vec<Event>, host_key: SigningKey) -> Result<Engine> {
    let Some(Event::ForestCreated { instance_id, forest_id, .. }) = events.first() else {
        return Err(PvfsError::BadInput { field: "genesis".into(), reason: "the first event must be ForestCreated".into() });
    };
    let (instance_id, forest_id) = (instance_id.clone(), forest_id.clone());
    let host_pub = crypto::pubkey_bytes(&host_key);
    let admitted = events.iter().any(|e| {
        matches!(e, Event::DeviceAuthorized { device_pubkey, device_index, .. }
            if *device_pubkey == host_pub && *device_index == MEMBER_DEVICE_INDEX)
    });
    if !admitted {
        return Err(PvfsError::BadInput { field: "genesis".into(), reason: "the genesis does not admit this box's key".into() });
    }
    if data_dir.join("log.db").exists() {
        return Err(PvfsError::AlreadyExists { kind: "forest", id: data_dir.to_string_lossy().into_owned() });
    }
    let created = !data_dir.exists();
    std::fs::create_dir_all(data_dir).map_err(|e| PvfsError::io("create data dir", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| PvfsError::io("chmod state dir", e))?;
    }
    let written = (|| -> Result<Engine> {
        {
            let mut conn = engine::open_connection(data_dir)?;
            projection::create_schema(&conn)?;
            let tx = conn.transaction().map_err(crate::error::map_db("begin genesis"))?;
            let mut chain = log_store::genesis_seed(&instance_id, &forest_id);
            let t = engine::now_ms();
            for (i, ev) in events.iter().enumerate() {
                chain = log_store::append_event(&tx, &chain, i as u64 + 1, ev, t)?;
            }
            tx.commit().map_err(crate::error::map_db("commit genesis"))?;
            projection::meta_set(&conn, "clean_shutdown", "0")?;
        }
        DeviceKeyCache { signing_key: host_key, device_index: MEMBER_DEVICE_INDEX }.save(data_dir)?;
        // The projection is empty: this open replays the whole genesis.
        Engine::open(data_dir)
    })();
    if written.is_err() {
        if created {
            let _ = std::fs::remove_dir_all(data_dir);
        } else {
            for f in std::fs::read_dir(data_dir).into_iter().flatten().flatten() {
                let _ = std::fs::remove_file(f.path());
            }
        }
    }
    written
}
