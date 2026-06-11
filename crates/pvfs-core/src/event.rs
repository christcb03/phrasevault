//! Events — spec §6. The canonical truth: PCE-encoded bodies, every mutable
//! event signed over a domain-separated BLAKE3 digest.

use crate::crypto;
use crate::encoding::{Dec, Enc};
use crate::error::{PvfsError, Result};
use crate::link::Link;
use crate::node::Node;

pub const K_FOREST_CREATED: &str = "ForestCreated";
pub const K_DEVICE_AUTHORIZED: &str = "DeviceAuthorized";
pub const K_DEVICE_REVOKED: &str = "DeviceRevoked";
pub const K_NODE_CREATED: &str = "NodeCreated";
pub const K_LINK_CREATED: &str = "LinkCreated";
pub const K_LINK_REMOVED: &str = "LinkRemoved";
pub const K_LINK_REORDERED: &str = "LinkReordered";
pub const K_LINK_SUPERSEDED: &str = "LinkSuperseded";
pub const K_LINK_SUSPENDED: &str = "LinkSuspended";
pub const K_LINK_UNSUSPENDED: &str = "LinkUnsuspended";
pub const K_FILE_LOCATION_ADDED: &str = "FileLocationAdded";
pub const K_FILE_LOCATION_REMOVED: &str = "FileLocationRemoved";
pub const K_NODE_PURGED: &str = "NodePurged";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    ForestCreated {
        instance_id: String,
        forest_id: String,
        root_node_id: String,
        created_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    DeviceAuthorized {
        device_pubkey: Vec<u8>,
        device_index: u64,
        authorized_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    DeviceRevoked {
        device_pubkey: Vec<u8>,
        revoked_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    NodeCreated(Node),
    LinkCreated(Link),
    LinkRemoved {
        link_id: String,
        removed_at: u64,
        removed_by: Vec<u8>,
        removal_sig: Vec<u8>,
    },
    LinkReordered {
        link_id: String,
        new_order_key: String,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    LinkSuperseded {
        old_link_id: String,
        new_link_id: String,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    LinkSuspended {
        link_id: String,
        suspended_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    LinkUnsuspended {
        link_id: String,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    FileLocationAdded {
        file_id: String,
        uri: String,
        added_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    FileLocationRemoved {
        file_id: String,
        uri: String,
        removed_at: u64,
        removed_by: Vec<u8>,
        removal_sig: Vec<u8>,
    },
    NodePurged {
        node_id: String,
        purged_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
}

// ---- signed-message digests (spec §6 table) --------------------------------

pub fn msg_forest_created(
    instance_id: &str,
    forest_id: &str,
    root_node_id: &str,
    created_at: u64,
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(instance_id)
        .string(forest_id)
        .string(root_node_id)
        .u64(created_at)
        .bytes(author);
    crypto::domain_digest("pvfs:forestcreated:v1:", &e.finish())
}

pub fn msg_device_authorized(
    device_pubkey: &[u8],
    device_index: u64,
    authorized_at: u64,
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.bytes(device_pubkey)
        .u64(device_index)
        .u64(authorized_at)
        .bytes(author);
    crypto::domain_digest("pvfs:deviceauthorized:v1:", &e.finish())
}

pub fn msg_device_revoked(device_pubkey: &[u8], revoked_at: u64, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.bytes(device_pubkey).u64(revoked_at).bytes(author);
    crypto::domain_digest("pvfs:devicerevoked:v1:", &e.finish())
}

pub fn msg_link_removed(link_id: &str, removed_at: u64, removed_by: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(link_id).u64(removed_at).bytes(removed_by);
    crypto::domain_digest("pvfs:linkremoved:v1:", &e.finish())
}

pub fn msg_link_reordered(link_id: &str, new_order_key: &str, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(link_id).string(new_order_key).bytes(author);
    crypto::domain_digest("pvfs:linkreordered:v1:", &e.finish())
}

pub fn msg_link_superseded(old_link_id: &str, new_link_id: &str, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(old_link_id).string(new_link_id).bytes(author);
    crypto::domain_digest("pvfs:linksuperseded:v1:", &e.finish())
}

pub fn msg_link_suspended(link_id: &str, suspended_at: u64, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(link_id).u64(suspended_at).bytes(author);
    crypto::domain_digest("pvfs:linksuspended:v1:", &e.finish())
}

pub fn msg_link_unsuspended(link_id: &str, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(link_id).bytes(author);
    crypto::domain_digest("pvfs:linkunsuspended:v1:", &e.finish())
}

pub fn msg_file_location_added(file_id: &str, uri: &str, added_at: u64, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(file_id).string(uri).u64(added_at).bytes(author);
    crypto::domain_digest("pvfs:filelocationadded:v1:", &e.finish())
}

pub fn msg_file_location_removed(
    file_id: &str,
    uri: &str,
    removed_at: u64,
    removed_by: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(file_id).string(uri).u64(removed_at).bytes(removed_by);
    crypto::domain_digest("pvfs:filelocationremoved:v1:", &e.finish())
}

pub fn msg_node_purged(node_id: &str, purged_at: u64, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(node_id).u64(purged_at).bytes(author);
    crypto::domain_digest("pvfs:nodepurged:v1:", &e.finish())
}

// ---- encode / decode --------------------------------------------------------

impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Event::ForestCreated { .. } => K_FOREST_CREATED,
            Event::DeviceAuthorized { .. } => K_DEVICE_AUTHORIZED,
            Event::DeviceRevoked { .. } => K_DEVICE_REVOKED,
            Event::NodeCreated(_) => K_NODE_CREATED,
            Event::LinkCreated(_) => K_LINK_CREATED,
            Event::LinkRemoved { .. } => K_LINK_REMOVED,
            Event::LinkReordered { .. } => K_LINK_REORDERED,
            Event::LinkSuperseded { .. } => K_LINK_SUPERSEDED,
            Event::LinkSuspended { .. } => K_LINK_SUSPENDED,
            Event::LinkUnsuspended { .. } => K_LINK_UNSUSPENDED,
            Event::FileLocationAdded { .. } => K_FILE_LOCATION_ADDED,
            Event::FileLocationRemoved { .. } => K_FILE_LOCATION_REMOVED,
            Event::NodePurged { .. } => K_NODE_PURGED,
        }
    }

    pub fn encode_body(&self) -> Vec<u8> {
        let mut e = Enc::new();
        match self {
            Event::ForestCreated {
                instance_id,
                forest_id,
                root_node_id,
                created_at,
                author,
                sig,
            } => {
                e.string(instance_id)
                    .string(forest_id)
                    .string(root_node_id)
                    .u64(*created_at)
                    .bytes(author)
                    .bytes(sig);
            }
            Event::DeviceAuthorized {
                device_pubkey,
                device_index,
                authorized_at,
                author,
                sig,
            } => {
                e.bytes(device_pubkey)
                    .u64(*device_index)
                    .u64(*authorized_at)
                    .bytes(author)
                    .bytes(sig);
            }
            Event::DeviceRevoked {
                device_pubkey,
                revoked_at,
                author,
                sig,
            } => {
                e.bytes(device_pubkey).u64(*revoked_at).bytes(author).bytes(sig);
            }
            Event::NodeCreated(n) => {
                e.string(&n.id)
                    .string(&n.node_type)
                    .string(&n.label)
                    .string(&n.visibility)
                    .bytes(&n.payload)
                    .boolean(n.is_temp)
                    .u64(n.creation_nonce)
                    .u64(n.created_at)
                    .bytes(&n.author)
                    .bytes(&n.sig);
            }
            Event::LinkCreated(l) => {
                e.string(&l.id)
                    .opt_string(l.parent_id.as_deref())
                    .string(&l.child_id)
                    .string(&l.link_type)
                    .u64(l.link_nonce)
                    .string(&l.order_key)
                    .u64(l.created_at)
                    .bytes(&l.author)
                    .bytes(&l.sig);
            }
            Event::LinkRemoved {
                link_id,
                removed_at,
                removed_by,
                removal_sig,
            } => {
                e.string(link_id).u64(*removed_at).bytes(removed_by).bytes(removal_sig);
            }
            Event::LinkReordered {
                link_id,
                new_order_key,
                author,
                sig,
            } => {
                e.string(link_id).string(new_order_key).bytes(author).bytes(sig);
            }
            Event::LinkSuperseded {
                old_link_id,
                new_link_id,
                author,
                sig,
            } => {
                e.string(old_link_id).string(new_link_id).bytes(author).bytes(sig);
            }
            Event::LinkSuspended {
                link_id,
                suspended_at,
                author,
                sig,
            } => {
                e.string(link_id).u64(*suspended_at).bytes(author).bytes(sig);
            }
            Event::LinkUnsuspended { link_id, author, sig } => {
                e.string(link_id).bytes(author).bytes(sig);
            }
            Event::FileLocationAdded {
                file_id,
                uri,
                added_at,
                author,
                sig,
            } => {
                e.string(file_id).string(uri).u64(*added_at).bytes(author).bytes(sig);
            }
            Event::FileLocationRemoved {
                file_id,
                uri,
                removed_at,
                removed_by,
                removal_sig,
            } => {
                e.string(file_id)
                    .string(uri)
                    .u64(*removed_at)
                    .bytes(removed_by)
                    .bytes(removal_sig);
            }
            Event::NodePurged {
                node_id,
                purged_at,
                author,
                sig,
            } => {
                e.string(node_id).u64(*purged_at).bytes(author).bytes(sig);
            }
        }
        e.finish()
    }

    pub fn decode(kind: &str, body: &[u8]) -> Result<Event> {
        let mut d = Dec::new(body, "event body");
        let ev = match kind {
            K_FOREST_CREATED => Event::ForestCreated {
                instance_id: d.string()?,
                forest_id: d.string()?,
                root_node_id: d.string()?,
                created_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_DEVICE_AUTHORIZED => Event::DeviceAuthorized {
                device_pubkey: d.bytes()?,
                device_index: d.u64()?,
                authorized_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_DEVICE_REVOKED => Event::DeviceRevoked {
                device_pubkey: d.bytes()?,
                revoked_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_NODE_CREATED => Event::NodeCreated(Node {
                id: d.string()?,
                node_type: d.string()?,
                label: d.string()?,
                visibility: d.string()?,
                payload: d.bytes()?,
                is_temp: d.boolean()?,
                creation_nonce: d.u64()?,
                created_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            }),
            K_LINK_CREATED => Event::LinkCreated(Link {
                id: d.string()?,
                parent_id: d.opt_string()?,
                child_id: d.string()?,
                link_type: d.string()?,
                link_nonce: d.u64()?,
                order_key: d.string()?,
                created_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
                removed_at: None,
                superseded_by: None,
                suspended_at: None,
            }),
            K_LINK_REMOVED => Event::LinkRemoved {
                link_id: d.string()?,
                removed_at: d.u64()?,
                removed_by: d.bytes()?,
                removal_sig: d.bytes()?,
            },
            K_LINK_REORDERED => Event::LinkReordered {
                link_id: d.string()?,
                new_order_key: d.string()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_LINK_SUPERSEDED => Event::LinkSuperseded {
                old_link_id: d.string()?,
                new_link_id: d.string()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_LINK_SUSPENDED => Event::LinkSuspended {
                link_id: d.string()?,
                suspended_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_LINK_UNSUSPENDED => Event::LinkUnsuspended {
                link_id: d.string()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_FILE_LOCATION_ADDED => Event::FileLocationAdded {
                file_id: d.string()?,
                uri: d.string()?,
                added_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_FILE_LOCATION_REMOVED => Event::FileLocationRemoved {
                file_id: d.string()?,
                uri: d.string()?,
                removed_at: d.u64()?,
                removed_by: d.bytes()?,
                removal_sig: d.bytes()?,
            },
            K_NODE_PURGED => Event::NodePurged {
                node_id: d.string()?,
                purged_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            other => {
                return Err(PvfsError::Encoding {
                    what: "event kind".into(),
                    offset: 0,
                    detail: format!("unknown event kind {other:?}"),
                })
            }
        };
        d.finish()?;
        Ok(ev)
    }

    /// Verify the event's own signature(s) — used on replay/sync (spec §6).
    pub fn verify_sig(&self) -> Result<()> {
        match self {
            Event::ForestCreated {
                instance_id,
                forest_id,
                root_node_id,
                created_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_forest_created(instance_id, forest_id, root_node_id, *created_at, author),
                sig,
            ),
            Event::DeviceAuthorized {
                device_pubkey,
                device_index,
                authorized_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_device_authorized(device_pubkey, *device_index, *authorized_at, author),
                sig,
            ),
            Event::DeviceRevoked {
                device_pubkey,
                revoked_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_device_revoked(device_pubkey, *revoked_at, author),
                sig,
            ),
            Event::NodeCreated(n) => n.verify(),
            Event::LinkCreated(l) => l.verify(),
            Event::LinkRemoved {
                link_id,
                removed_at,
                removed_by,
                removal_sig,
            } => crypto::verify_digest(
                removed_by,
                &msg_link_removed(link_id, *removed_at, removed_by),
                removal_sig,
            ),
            Event::LinkReordered {
                link_id,
                new_order_key,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_link_reordered(link_id, new_order_key, author),
                sig,
            ),
            Event::LinkSuperseded {
                old_link_id,
                new_link_id,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_link_superseded(old_link_id, new_link_id, author),
                sig,
            ),
            Event::LinkSuspended {
                link_id,
                suspended_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_link_suspended(link_id, *suspended_at, author),
                sig,
            ),
            Event::LinkUnsuspended { link_id, author, sig } => {
                crypto::verify_digest(author, &msg_link_unsuspended(link_id, author), sig)
            }
            Event::FileLocationAdded {
                file_id,
                uri,
                added_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_file_location_added(file_id, uri, *added_at, author),
                sig,
            ),
            Event::FileLocationRemoved {
                file_id,
                uri,
                removed_at,
                removed_by,
                removal_sig,
            } => crypto::verify_digest(
                removed_by,
                &msg_file_location_removed(file_id, uri, *removed_at, removed_by),
                removal_sig,
            ),
            Event::NodePurged {
                node_id,
                purged_at,
                author,
                sig,
            } => crypto::verify_digest(author, &msg_node_purged(node_id, *purged_at, author), sig),
        }
    }
}
