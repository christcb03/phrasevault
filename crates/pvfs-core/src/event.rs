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
pub const K_FOLDER_BOUND: &str = "FolderBound";
pub const K_FOLDER_UNBOUND: &str = "FolderUnbound";
pub const K_ACL_SET: &str = "AclSet";
pub const K_MEMBER_TAGGED: &str = "MemberTagged";
pub const K_SECURE_BLOB_UPDATED: &str = "SecureBlobUpdated";
pub const K_ROOT_ROTATED: &str = "RootRotated";
pub const K_RECOVERY_KEY_REGISTERED: &str = "RecoveryKeyRegistered";
pub const K_RECOVERY_KEY_REVOKED: &str = "RecoveryKeyRevoked";

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
    /// Re-anchor forest authority to a new root key (doc 15 §C2, seed rotation).
    /// Valid iff `author` is the current root of the lineage or a registered
    /// recovery key; first valid one in the log wins. `forest_id`/ids unchanged.
    RootRotated {
        new_root_pubkey: Vec<u8>,
        rotated_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// Register an offline recovery key that may author a `RootRotated`
    /// (doc 15 §C5). `author` must be the current root (phrase-authenticated by
    /// construction — the companion never signs this; §6 decision 4).
    RecoveryKeyRegistered {
        recovery_pubkey: Vec<u8>,
        registered_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// De-register a recovery key (doc 15 §C6a). `author` must be the current
    /// root. (A `RootRotated` also clears ALL recovery keys — this is for
    /// retiring one without rotating.)
    RecoveryKeyRevoked {
        recovery_pubkey: Vec<u8>,
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
    FolderBound {
        folder_id: String,
        source_uri: String,
        recursive: bool,
        auto_index: bool,
        extensions: String,
        hash_policy: String,
        bound_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    FolderUnbound {
        folder_id: String,
        unbound_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// Set (or, with rights 0, clear) one principal's rights on a node (doc 06 §4).
    AclSet {
        node_id: String,
        principal_kind: u64,
        principal_id: Vec<u8>,
        rights: u64,
        set_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// Grant (`granted`) or remove a tag from a member key (doc 09 §1).
    MemberTagged {
        member_pubkey: Vec<u8>,
        tag: String,
        granted: bool,
        set_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// Advance a secure blob's content-free ledger (doc 12 §8.2): "the
    /// ciphertext at `blob_id`'s location is now `content_hash` (`size` bytes),
    /// changed by `author`". Never any content. Author must hold write (w).
    SecureBlobUpdated {
        blob_id: String,
        content_hash: Vec<u8>, // 32 bytes — hash of the ciphertext (doc 12 §8.4)
        size: u64,
        updated_at: u64,
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

pub fn msg_root_rotated(new_root_pubkey: &[u8], rotated_at: u64, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.bytes(new_root_pubkey).u64(rotated_at).bytes(author);
    crypto::domain_digest("pvfs:rootrotated:v1:", &e.finish())
}

pub fn msg_recovery_key_registered(
    recovery_pubkey: &[u8],
    registered_at: u64,
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.bytes(recovery_pubkey).u64(registered_at).bytes(author);
    crypto::domain_digest("pvfs:recoverykey:v1:", &e.finish())
}

pub fn msg_recovery_key_revoked(recovery_pubkey: &[u8], revoked_at: u64, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.bytes(recovery_pubkey).u64(revoked_at).bytes(author);
    crypto::domain_digest("pvfs:recoverykeyrevoked:v1:", &e.finish())
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

#[allow(clippy::too_many_arguments)]
pub fn msg_folder_bound(
    folder_id: &str,
    source_uri: &str,
    recursive: bool,
    auto_index: bool,
    extensions: &str,
    hash_policy: &str,
    bound_at: u64,
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(folder_id)
        .string(source_uri)
        .boolean(recursive)
        .boolean(auto_index)
        .string(extensions)
        .string(hash_policy)
        .u64(bound_at)
        .bytes(author);
    crypto::domain_digest("pvfs:folderbound:v1:", &e.finish())
}

pub fn msg_folder_unbound(folder_id: &str, unbound_at: u64, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(folder_id).u64(unbound_at).bytes(author);
    crypto::domain_digest("pvfs:folderunbound:v1:", &e.finish())
}

pub fn msg_acl_set(
    node_id: &str,
    principal_kind: u64,
    principal_id: &[u8],
    rights: u64,
    set_at: u64,
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(node_id)
        .u64(principal_kind)
        .bytes(principal_id)
        .u64(rights)
        .u64(set_at)
        .bytes(author);
    crypto::domain_digest("pvfs:aclset:v1:", &e.finish())
}

pub fn msg_member_tagged(
    member_pubkey: &[u8],
    tag: &str,
    granted: bool,
    set_at: u64,
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.bytes(member_pubkey)
        .string(tag)
        .boolean(granted)
        .u64(set_at)
        .bytes(author);
    crypto::domain_digest("pvfs:membertagged:v1:", &e.finish())
}

pub fn msg_secure_blob_updated(
    blob_id: &str,
    content_hash: &[u8],
    size: u64,
    updated_at: u64,
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(blob_id)
        .bytes(content_hash)
        .u64(size)
        .u64(updated_at)
        .bytes(author);
    crypto::domain_digest("pvfs:secureblob:v1:", &e.finish())
}

// ---- encode / decode --------------------------------------------------------

impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Event::ForestCreated { .. } => K_FOREST_CREATED,
            Event::DeviceAuthorized { .. } => K_DEVICE_AUTHORIZED,
            Event::DeviceRevoked { .. } => K_DEVICE_REVOKED,
            Event::RootRotated { .. } => K_ROOT_ROTATED,
            Event::RecoveryKeyRegistered { .. } => K_RECOVERY_KEY_REGISTERED,
            Event::RecoveryKeyRevoked { .. } => K_RECOVERY_KEY_REVOKED,
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
            Event::FolderBound { .. } => K_FOLDER_BOUND,
            Event::FolderUnbound { .. } => K_FOLDER_UNBOUND,
            Event::AclSet { .. } => K_ACL_SET,
            Event::MemberTagged { .. } => K_MEMBER_TAGGED,
            Event::SecureBlobUpdated { .. } => K_SECURE_BLOB_UPDATED,
        }
    }

    /// The public key whose signature authorizes this event. For removal events
    /// the authorizing key is `removed_by`; for genesis and device certificates
    /// it is the identity root. Used by replay to enforce author-authorization.
    pub fn author(&self) -> &[u8] {
        match self {
            Event::ForestCreated { author, .. }
            | Event::DeviceAuthorized { author, .. }
            | Event::DeviceRevoked { author, .. }
            | Event::RootRotated { author, .. }
            | Event::RecoveryKeyRegistered { author, .. }
            | Event::RecoveryKeyRevoked { author, .. }
            | Event::LinkReordered { author, .. }
            | Event::LinkSuperseded { author, .. }
            | Event::LinkSuspended { author, .. }
            | Event::LinkUnsuspended { author, .. }
            | Event::FileLocationAdded { author, .. }
            | Event::NodePurged { author, .. }
            | Event::FolderBound { author, .. }
            | Event::FolderUnbound { author, .. }
            | Event::AclSet { author, .. }
            | Event::MemberTagged { author, .. }
            | Event::SecureBlobUpdated { author, .. } => author,
            Event::NodeCreated(n) => &n.author,
            Event::LinkCreated(l) => &l.author,
            Event::LinkRemoved { removed_by, .. } | Event::FileLocationRemoved { removed_by, .. } => {
                removed_by
            }
        }
    }

    /// Attach an author signature to an as-yet-unsigned event (member-write
    /// commit, doc 07 §5). Only the member-signable kinds are handled; genesis
    /// and device-certificate events are root-signed and never go this path.
    pub fn set_author_sig(&mut self, sig: Vec<u8>) {
        match self {
            Event::NodeCreated(n) => n.sig = sig,
            Event::LinkCreated(l) => l.sig = sig,
            Event::AclSet { sig: s, .. }
            | Event::MemberTagged { sig: s, .. }
            | Event::SecureBlobUpdated { sig: s, .. }
            | Event::DeviceAuthorized { sig: s, .. }
            | Event::DeviceRevoked { sig: s, .. }
            | Event::RootRotated { sig: s, .. }
            | Event::RecoveryKeyRegistered { sig: s, .. }
            | Event::RecoveryKeyRevoked { sig: s, .. }
            | Event::FileLocationAdded { sig: s, .. }
            | Event::LinkRemoved { removal_sig: s, .. }
            | Event::FileLocationRemoved { removal_sig: s, .. } => *s = sig,
            _ => {}
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
            Event::RootRotated {
                new_root_pubkey,
                rotated_at,
                author,
                sig,
            } => {
                e.bytes(new_root_pubkey).u64(*rotated_at).bytes(author).bytes(sig);
            }
            Event::RecoveryKeyRegistered {
                recovery_pubkey,
                registered_at,
                author,
                sig,
            } => {
                e.bytes(recovery_pubkey).u64(*registered_at).bytes(author).bytes(sig);
            }
            Event::RecoveryKeyRevoked {
                recovery_pubkey,
                revoked_at,
                author,
                sig,
            } => {
                e.bytes(recovery_pubkey).u64(*revoked_at).bytes(author).bytes(sig);
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
            Event::FolderBound {
                folder_id,
                source_uri,
                recursive,
                auto_index,
                extensions,
                hash_policy,
                bound_at,
                author,
                sig,
            } => {
                e.string(folder_id)
                    .string(source_uri)
                    .boolean(*recursive)
                    .boolean(*auto_index)
                    .string(extensions)
                    .string(hash_policy)
                    .u64(*bound_at)
                    .bytes(author)
                    .bytes(sig);
            }
            Event::FolderUnbound {
                folder_id,
                unbound_at,
                author,
                sig,
            } => {
                e.string(folder_id).u64(*unbound_at).bytes(author).bytes(sig);
            }
            Event::AclSet {
                node_id,
                principal_kind,
                principal_id,
                rights,
                set_at,
                author,
                sig,
            } => {
                e.string(node_id)
                    .u64(*principal_kind)
                    .bytes(principal_id)
                    .u64(*rights)
                    .u64(*set_at)
                    .bytes(author)
                    .bytes(sig);
            }
            Event::MemberTagged {
                member_pubkey,
                tag,
                granted,
                set_at,
                author,
                sig,
            } => {
                e.bytes(member_pubkey)
                    .string(tag)
                    .boolean(*granted)
                    .u64(*set_at)
                    .bytes(author)
                    .bytes(sig);
            }
            Event::SecureBlobUpdated {
                blob_id,
                content_hash,
                size,
                updated_at,
                author,
                sig,
            } => {
                e.string(blob_id)
                    .bytes(content_hash)
                    .u64(*size)
                    .u64(*updated_at)
                    .bytes(author)
                    .bytes(sig);
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
            K_ROOT_ROTATED => Event::RootRotated {
                new_root_pubkey: d.bytes()?,
                rotated_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_RECOVERY_KEY_REGISTERED => Event::RecoveryKeyRegistered {
                recovery_pubkey: d.bytes()?,
                registered_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_RECOVERY_KEY_REVOKED => Event::RecoveryKeyRevoked {
                recovery_pubkey: d.bytes()?,
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
            K_FOLDER_BOUND => Event::FolderBound {
                folder_id: d.string()?,
                source_uri: d.string()?,
                recursive: d.boolean()?,
                auto_index: d.boolean()?,
                extensions: d.string()?,
                hash_policy: d.string()?,
                bound_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_FOLDER_UNBOUND => Event::FolderUnbound {
                folder_id: d.string()?,
                unbound_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_ACL_SET => Event::AclSet {
                node_id: d.string()?,
                principal_kind: d.u64()?,
                principal_id: d.bytes()?,
                rights: d.u64()?,
                set_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_MEMBER_TAGGED => Event::MemberTagged {
                member_pubkey: d.bytes()?,
                tag: d.string()?,
                granted: d.boolean()?,
                set_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_SECURE_BLOB_UPDATED => Event::SecureBlobUpdated {
                blob_id: d.string()?,
                content_hash: d.bytes()?,
                size: d.u64()?,
                updated_at: d.u64()?,
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
            Event::RootRotated {
                new_root_pubkey,
                rotated_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_root_rotated(new_root_pubkey, *rotated_at, author),
                sig,
            ),
            Event::RecoveryKeyRegistered {
                recovery_pubkey,
                registered_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_recovery_key_registered(recovery_pubkey, *registered_at, author),
                sig,
            ),
            Event::RecoveryKeyRevoked {
                recovery_pubkey,
                revoked_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_recovery_key_revoked(recovery_pubkey, *revoked_at, author),
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
            Event::FolderBound {
                folder_id,
                source_uri,
                recursive,
                auto_index,
                extensions,
                hash_policy,
                bound_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_folder_bound(
                    folder_id,
                    source_uri,
                    *recursive,
                    *auto_index,
                    extensions,
                    hash_policy,
                    *bound_at,
                    author,
                ),
                sig,
            ),
            Event::FolderUnbound {
                folder_id,
                unbound_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_folder_unbound(folder_id, *unbound_at, author),
                sig,
            ),
            Event::AclSet {
                node_id,
                principal_kind,
                principal_id,
                rights,
                set_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_acl_set(node_id, *principal_kind, principal_id, *rights, *set_at, author),
                sig,
            ),
            Event::MemberTagged {
                member_pubkey,
                tag,
                granted,
                set_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_member_tagged(member_pubkey, tag, *granted, *set_at, author),
                sig,
            ),
            Event::SecureBlobUpdated {
                blob_id,
                content_hash,
                size,
                updated_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_secure_blob_updated(blob_id, content_hash, *size, *updated_at, author),
                sig,
            ),
        }
    }
}
