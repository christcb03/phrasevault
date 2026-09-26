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
/// D81 — unbind ONE root of a folder that has several. A NEW kind rather than a
/// field on `FolderUnbound`, because that event means "this folder is bound
/// nowhere" to every box already running, and quietly narrowing it would make an
/// old box and a new one disagree about the same log. An old box sees this as
/// `Event::Unknown`, retains it, and reports itself behind (D72 Part A).
pub const K_FOLDER_UNBOUND_ROOT: &str = "FolderUnboundRoot";
/// D72 Part B — a link's label. Mirrors `LinkReordered`: a signed event that
/// changes a MUTABLE attribute of an edge, leaving the edge's identity alone.
/// Old binaries (post-Part-A) see this as `Event::Unknown`, ignore it, and go
/// on using node labels — which is what makes labels-on-links ROLL.
pub const K_LINK_RELABELED: &str = "LinkRelabeled";
/// D76 — what a media file IS, measured: resolution, bit depth, HDR, bitrate.
///
/// A separate EVENT rather than a payload field, because the payload is inside
/// the node's id preimage — adding to it would change every node's identity.
/// Same reasoning that put labels on links (D72).
pub const K_MEDIA_QUALITY: &str = "MediaQuality";
pub const K_ACL_SET: &str = "AclSet";
pub const K_MEMBER_TAGGED: &str = "MemberTagged";
pub const K_SECURE_BLOB_UPDATED: &str = "SecureBlobUpdated";
pub const K_ROOT_ROTATED: &str = "RootRotated";
pub const K_RECOVERY_KEY_REGISTERED: &str = "RecoveryKeyRegistered";
pub const K_RECOVERY_KEY_REVOKED: &str = "RecoveryKeyRevoked";
pub const K_REGION_MARKED: &str = "RegionMarked";
pub const K_REGION_UNMARKED: &str = "RegionUnmarked";
pub const K_REGION_BASELINE: &str = "RegionBaseline";
pub const K_SUB_REGION_HEAD: &str = "SubRegionHead";
pub const K_REGION_DRAIN_SET: &str = "RegionDrainSet";
pub const K_NODE_MOVED_OUT: &str = "NodeMovedOut";
pub const K_NODE_MOVED_IN: &str = "NodeMovedIn";
pub const K_CHUNK_MANIFEST_RECORDED: &str = "ChunkManifestRecorded";
/// PVOS D192 — from here on the forest's authority events must be signed for
/// THIS forest (see [`Event::CertificatesBound`]).
pub const K_CERTS_BOUND: &str = "CertificatesBound";

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
    /// PVOS D192 — the forest binds its certificates: from here on every
    /// forest-authority event (device certificates, root rotation, recovery
    /// keys, member tags) must be signed for THIS forest — its v2 digest
    /// carries the forest id — and one that verifies only in the older form
    /// is refused. Earlier ones stay valid (history). Authored by the current
    /// root or an admin device: binding only takes authority away. The first
    /// in the log counts. A forest made by a D192 build is born bound (a v2
    /// genesis) and never carries one.
    CertificatesBound {
        at: u64,
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
    /// D72 Part B — the name this edge gives its child.
    LinkRelabeled {
        link_id: String,
        label: String,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// D76 — a measurement of a file's media quality, and WHERE it came from.
    ///
    /// `source` is provenance, not decoration: `arr` (the *arrs' own probe,
    /// captured at ingest), `probe` (ours), `derived` (computed from size and
    /// duration). A later, better measurement supersedes an earlier one, and
    /// knowing which is which is how that ordering stays honest.
    MediaQuality {
        node_id: String,
        /// Canonical JSON — see `MediaQuality` in `media.rs`.
        quality: String,
        source: String,
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
    /// P7.0 (doc 20 §2, doc 13 §B): `node_id` becomes a region boundary —
    /// its contains-closure (minus nested regions) is its own replication/
    /// compaction unit. Admin-authored structural event.
    RegionMarked {
        node_id: String,
        marked_at: u64,
        /// D125: "" = a log region (the P7.0 form, byte-identical on the wire);
        /// "catalogue" = the region catalogues its own files and has no log.
        /// Trailing on the wire and written only when non-empty — the AclSet
        /// `expires_at` pattern, so pre-D125 bodies decode unchanged.
        kind: String,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// P7.0: the boundary is removed; the subtree folds back into the
    /// enclosing region.
    RegionUnmarked {
        node_id: String,
        unmarked_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// P7.2a (doc 20 §2.3): the mark-time state commitment for `node_id`'s
    /// region — `state_root` is the canonical subtree state hash the new
    /// region log's genesis seed binds (with this row's own seq). Appended
    /// in the enclosing region's log, right after the mark it belongs to.
    RegionBaseline {
        node_id: String,
        state_root: Vec<u8>,
        at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// P7.2a (doc 20 §2.3): head commitment — the enclosing log attests that
    /// region `node_id`'s log reaches (`head_seq`, `head_hash`). The
    /// hash-linked tree of logs; the final one (in the unmark commit) seals
    /// the generation.
    SubRegionHead {
        node_id: String,
        head_seq: u64,
        head_hash: Vec<u8>,
        at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// D127 (doc 26 §7.3): a catalogue region drains (is staging — its
    /// copies drain into the library) or does not. In the LOG, not local
    /// placement, so every box agrees which copy is redundant: two draining
    /// boxes each believing the other was the library would both trash.
    RegionDrainSet {
        node_id: String,
        drains: bool,
        at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// P7.2c (doc 20 §2.5): the source half of a cross-region move — the
    /// node's home link `link_id` is removed at `removed_at`, the node
    /// departing for `dest_region` (whose last committed head is the causal
    /// cross-reference; `(0, "")` = the top region). Authors in the source
    /// region's log.
    NodeMovedOut {
        node_id: String,
        link_id: String,
        removed_at: u64,
        dest_region: String,
        dest_head_seq: u64,
        dest_head_hash: Vec<u8>,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// P7.2c: the destination half — the new home `link`, licensed to
    /// supersede `removed_link_id` (empty = an orphan adoption, no source
    /// link removed) at the same shared `removed_at`. Authors in the
    /// destination region's log and flips the node's sticky region. The
    /// link's own signature authorizes (exactly `LinkCreated`'s posture);
    /// the auxiliary fields are chain-bound, like a link's order key.
    NodeMovedIn {
        link: Link,
        removed_link_id: String,
        removed_at: u64,
        src_region: String,
        src_head_seq: u64,
        src_head_hash: Vec<u8>,
    },
    /// P9.1 (doc 22 §2): the OWNER attests a file's chunk layout —
    /// `manifest_root = BLAKE3("pvfs:manifest:v1:" || concat(chunk hashes))`
    /// for the bytes whose whole-file hash is `content_hash`. Admin-tier on
    /// replay: early serving trusts this INSTEAD of the whole-file gate.
    ChunkManifestRecorded {
        file_id: String,
        content_hash: String,
        chunk_size: u64,
        manifest_root: Vec<u8>,
        at: u64,
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
    /// One root removed from a multi-root folder (D81).
    FolderUnboundRoot {
        folder_id: String,
        source_uri: String,
        unbound_at: u64,
        author: Vec<u8>,
        sig: Vec<u8>,
    },
    /// Set (or, with rights 0, clear) one principal's rights on a node (doc 06 §4).
    /// `expires_at` (doc 13 Q-E1, 1.1): ms epoch after which the grant is inert;
    /// 0 = never. On the wire it is a trailing field written only when nonzero,
    /// so pre-1.1 events decode unchanged and a no-expiry event is byte-identical
    /// to its 1.0 form.
    AclSet {
        node_id: String,
        principal_kind: u64,
        principal_id: Vec<u8>,
        rights: u64,
        set_at: u64,
        expires_at: u64,
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
    /// D72 Part A — an event kind this binary does not know.
    ///
    /// Kept rather than rejected, so a newer box can write a kind an older box
    /// has never heard of and the older box still replays the log. That is
    /// cryptographically safe: the chain hash covers `(seq, kind, body,
    /// written_at)` — the RAW bytes — so integrity is verifiable without
    /// understanding meaning.
    ///
    /// It is NOT semantically safe to pretend it applied. Every fold that
    /// meets one records it, and the box reports itself as not fully
    /// understanding its own forest (§5.A.3). Tolerating an unknown event must
    /// never look like having applied it.
    Unknown { kind: String, body: Vec<u8> },
}

// ---- signed-message digests (spec §6 table) --------------------------------

/// Genesis. `born_bound` (PVOS D192): the v2 domain, which makes the forest
/// bound from its first event — its certificates are signed for it alone
/// ([`Event::CertificatesBound`]). The fields are the same either way.
pub fn msg_forest_created(
    instance_id: &str,
    forest_id: &str,
    root_node_id: &str,
    created_at: u64,
    author: &[u8],
    born_bound: bool,
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(instance_id)
        .string(forest_id)
        .string(root_node_id)
        .u64(created_at)
        .bytes(author);
    let v = if born_bound { "v2" } else { "v1" };
    crypto::domain_digest(&format!("pvfs:forestcreated:{v}:"), &e.finish())
}

/// PVOS D192 — a forest-authority digest. `forest: None` is the v1 form,
/// signed without the forest (valid only in a forest not yet bound);
/// `Some(id)` is v2, the forest id first, under the `:v2:` domain — a
/// certificate for that forest and no other. The fields are the same.
fn authority_digest(name: &str, forest: Option<&str>, fields: impl FnOnce(&mut Enc)) -> [u8; 32] {
    let mut e = Enc::new();
    if let Some(f) = forest {
        e.string(f);
    }
    fields(&mut e);
    let v = if forest.is_some() { "v2" } else { "v1" };
    crypto::domain_digest(&format!("pvfs:{name}:{v}:"), &e.finish())
}

pub fn msg_root_rotated(forest: Option<&str>, new_root_pubkey: &[u8], rotated_at: u64, author: &[u8]) -> [u8; 32] {
    authority_digest("rootrotated", forest, |e| {
        e.bytes(new_root_pubkey).u64(rotated_at).bytes(author);
    })
}

pub fn msg_recovery_key_registered(
    forest: Option<&str>,
    recovery_pubkey: &[u8],
    registered_at: u64,
    author: &[u8],
) -> [u8; 32] {
    authority_digest("recoverykey", forest, |e| {
        e.bytes(recovery_pubkey).u64(registered_at).bytes(author);
    })
}

pub fn msg_recovery_key_revoked(
    forest: Option<&str>,
    recovery_pubkey: &[u8],
    revoked_at: u64,
    author: &[u8],
) -> [u8; 32] {
    authority_digest("recoverykeyrevoked", forest, |e| {
        e.bytes(recovery_pubkey).u64(revoked_at).bytes(author);
    })
}

pub fn msg_device_authorized(
    forest: Option<&str>,
    device_pubkey: &[u8],
    device_index: u64,
    authorized_at: u64,
    author: &[u8],
) -> [u8; 32] {
    authority_digest("deviceauthorized", forest, |e| {
        e.bytes(device_pubkey).u64(device_index).u64(authorized_at).bytes(author);
    })
}

pub fn msg_device_revoked(forest: Option<&str>, device_pubkey: &[u8], revoked_at: u64, author: &[u8]) -> [u8; 32] {
    authority_digest("devicerevoked", forest, |e| {
        e.bytes(device_pubkey).u64(revoked_at).bytes(author);
    })
}

/// PVOS D192 — [`Event::CertificatesBound`]: always for one forest.
pub fn msg_certs_bound(forest_id: &str, at: u64, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(forest_id).u64(at).bytes(author);
    crypto::domain_digest("pvfs:certsbound:v1:", &e.finish())
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

/// D72 Part B. The label IS signed — it is content someone asserted, not
/// incidental state — but it is NOT part of the link's id preimage, so
/// renaming never changes the edge (doc 01 §5, the `order_key` precedent).
pub fn msg_link_relabeled(link_id: &str, label: &str, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(link_id).string(label).bytes(author);
    crypto::domain_digest("pvfs:linkrelabeled:v1:", &e.finish())
}

/// D76 — the signed preimage for a quality measurement.
pub fn msg_media_quality(node_id: &str, quality: &str, source: &str, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(node_id).string(quality).string(source).bytes(author);
    crypto::domain_digest("pvfs:mediaquality:v1:", &e.finish())
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

pub fn msg_region_marked(node_id: &str, marked_at: u64, kind: &str, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(node_id).u64(marked_at);
    if kind.is_empty() {
        e.bytes(author);
        crypto::domain_digest("pvfs:regionmarked:v1:", &e.finish())
    } else {
        e.string(kind).bytes(author);
        crypto::domain_digest("pvfs:regionmarked:v2:", &e.finish())
    }
}

pub fn msg_region_unmarked(node_id: &str, unmarked_at: u64, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(node_id).u64(unmarked_at).bytes(author);
    crypto::domain_digest("pvfs:regionunmarked:v1:", &e.finish())
}

pub fn msg_region_baseline(node_id: &str, state_root: &[u8], at: u64, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(node_id).bytes(state_root).u64(at).bytes(author);
    crypto::domain_digest("pvfs:regionbaseline:v1:", &e.finish())
}

pub fn msg_region_drain_set(node_id: &str, drains: bool, at: u64, author: &[u8]) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(node_id).u64(drains as u64).u64(at).bytes(author);
    crypto::domain_digest("pvfs:regiondrainset:v1:", &e.finish())
}

pub fn msg_sub_region_head(
    node_id: &str,
    head_seq: u64,
    head_hash: &[u8],
    at: u64,
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(node_id).u64(head_seq).bytes(head_hash).u64(at).bytes(author);
    crypto::domain_digest("pvfs:subregionhead:v1:", &e.finish())
}

pub fn msg_chunk_manifest_recorded(
    file_id: &str,
    content_hash: &str,
    chunk_size: u64,
    manifest_root: &[u8],
    at: u64,
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(file_id)
        .string(content_hash)
        .u64(chunk_size)
        .bytes(manifest_root)
        .u64(at)
        .bytes(author);
    crypto::domain_digest("pvfs:chunkmanifest:v1:", &e.finish())
}

#[allow(clippy::too_many_arguments)]
pub fn msg_node_moved_out(
    node_id: &str,
    link_id: &str,
    removed_at: u64,
    dest_region: &str,
    dest_head_seq: u64,
    dest_head_hash: &[u8],
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(node_id)
        .string(link_id)
        .u64(removed_at)
        .string(dest_region)
        .u64(dest_head_seq)
        .bytes(dest_head_hash)
        .bytes(author);
    crypto::domain_digest("pvfs:nodemovedout:v1:", &e.finish())
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

/// `expires_at == 0` (no expiry) keeps the v1 domain and message bytes, so every
/// pre-1.1 signature still verifies; an expiring grant signs under a fresh v2
/// domain that covers the expiry, so the two can never be confused.
pub fn msg_folder_unbound_root(
    folder_id: &str,
    source_uri: &str,
    unbound_at: u64,
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(folder_id)
        .string(source_uri)
        .u64(unbound_at)
        .bytes(author);
    crypto::domain_digest("pvfs:folderunboundroot:v1:", &e.finish())
}

pub fn msg_acl_set(
    node_id: &str,
    principal_kind: u64,
    principal_id: &[u8],
    rights: u64,
    set_at: u64,
    expires_at: u64,
    author: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(node_id)
        .u64(principal_kind)
        .bytes(principal_id)
        .u64(rights)
        .u64(set_at);
    if expires_at == 0 {
        e.bytes(author);
        crypto::domain_digest("pvfs:aclset:v1:", &e.finish())
    } else {
        e.u64(expires_at).bytes(author);
        crypto::domain_digest("pvfs:aclset:v2:", &e.finish())
    }
}

pub fn msg_member_tagged(
    forest: Option<&str>,
    member_pubkey: &[u8],
    tag: &str,
    granted: bool,
    set_at: u64,
    author: &[u8],
) -> [u8; 32] {
    authority_digest("membertagged", forest, |e| {
        e.bytes(member_pubkey).string(tag).boolean(granted).u64(set_at).bytes(author);
    })
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

/// Does THIS binary understand `kind`?
///
/// The migration path needs this: a box that folded an event as `Unknown` and
/// later gained the code to read it cannot cheaply migrate — its projection is
/// missing whatever that event carried, and only a replay can recover it.
/// Kept next to `decode` so the two lists cannot drift apart.
pub fn is_known_kind(kind: &str) -> bool {
    !matches!(Event::decode(kind, &[]), Ok(Event::Unknown { .. }))
}

/// PVOS D192 — what an event's signature is checked against: the forest it
/// sits in, and whether that forest has bound its certificates (born bound,
/// or a [`Event::CertificatesBound`] earlier in its log).
#[derive(Clone, Copy, Debug)]
pub struct SigContext<'a> {
    pub forest_id: &'a str,
    pub bound: bool,
}

/// A forest-authority signature: for this forest (v2), or — only while it
/// is not bound — the older form without a forest (v1). A certificate
/// signed for another forest never verifies here: its digest names that one.
fn verify_authority(
    ctx: &SigContext<'_>,
    author: &[u8],
    sig: &[u8],
    digest: impl Fn(Option<&str>) -> [u8; 32],
) -> Result<()> {
    if crypto::verify_digest(author, &digest(Some(ctx.forest_id)), sig).is_ok() {
        return Ok(());
    }
    if !ctx.bound {
        return crypto::verify_digest(author, &digest(None), sig);
    }
    Err(PvfsError::Integrity {
        kind: "event",
        id: format!("certificate not signed for forest {} (it binds its certificates)", ctx.forest_id),
        reason: crate::error::IntegrityReason::SignatureInvalid,
    })
}

impl Event {
    /// PVOS D192 — a genesis signed in the v2 form: the forest is bound from
    /// its first event. `false` for any other event, or a v1 genesis.
    pub fn genesis_born_bound(&self) -> bool {
        match self {
            Event::ForestCreated { instance_id, forest_id, root_node_id, created_at, author, sig } => {
                crypto::verify_digest(
                    author,
                    &msg_forest_created(instance_id, forest_id, root_node_id, *created_at, author, true),
                    sig,
                )
                .is_ok()
            }
            _ => false,
        }
    }

    pub fn kind(&self) -> &str {
        match self {
            Event::ForestCreated { .. } => K_FOREST_CREATED,
            Event::DeviceAuthorized { .. } => K_DEVICE_AUTHORIZED,
            Event::DeviceRevoked { .. } => K_DEVICE_REVOKED,
            Event::RootRotated { .. } => K_ROOT_ROTATED,
            Event::RecoveryKeyRegistered { .. } => K_RECOVERY_KEY_REGISTERED,
            Event::RecoveryKeyRevoked { .. } => K_RECOVERY_KEY_REVOKED,
            Event::CertificatesBound { .. } => K_CERTS_BOUND,
            Event::NodeCreated(_) => K_NODE_CREATED,
            Event::LinkCreated(_) => K_LINK_CREATED,
            Event::LinkRemoved { .. } => K_LINK_REMOVED,
            Event::LinkReordered { .. } => K_LINK_REORDERED,
            Event::LinkRelabeled { .. } => K_LINK_RELABELED,
            Event::MediaQuality { .. } => K_MEDIA_QUALITY,
            Event::LinkSuperseded { .. } => K_LINK_SUPERSEDED,
            Event::LinkSuspended { .. } => K_LINK_SUSPENDED,
            Event::LinkUnsuspended { .. } => K_LINK_UNSUSPENDED,
            Event::FileLocationAdded { .. } => K_FILE_LOCATION_ADDED,
            Event::RegionMarked { .. } => K_REGION_MARKED,
            Event::RegionUnmarked { .. } => K_REGION_UNMARKED,
            Event::RegionBaseline { .. } => K_REGION_BASELINE,
            Event::SubRegionHead { .. } => K_SUB_REGION_HEAD,
            Event::RegionDrainSet { .. } => K_REGION_DRAIN_SET,
            Event::NodeMovedOut { .. } => K_NODE_MOVED_OUT,
            Event::NodeMovedIn { .. } => K_NODE_MOVED_IN,
            Event::ChunkManifestRecorded { .. } => K_CHUNK_MANIFEST_RECORDED,
            Event::FileLocationRemoved { .. } => K_FILE_LOCATION_REMOVED,
            Event::NodePurged { .. } => K_NODE_PURGED,
            Event::FolderBound { .. } => K_FOLDER_BOUND,
            Event::FolderUnbound { .. } => K_FOLDER_UNBOUND,
            Event::FolderUnboundRoot { .. } => K_FOLDER_UNBOUND_ROOT,
            Event::AclSet { .. } => K_ACL_SET,
            Event::MemberTagged { .. } => K_MEMBER_TAGGED,
            Event::SecureBlobUpdated { .. } => K_SECURE_BLOB_UPDATED,
            Event::Unknown { kind, .. } => kind.as_str(),
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
            | Event::CertificatesBound { author, .. }
            | Event::LinkReordered { author, .. }
            | Event::LinkRelabeled { author, .. }
            | Event::MediaQuality { author, .. }
            | Event::LinkSuperseded { author, .. }
            | Event::LinkSuspended { author, .. }
            | Event::LinkUnsuspended { author, .. }
            | Event::FileLocationAdded { author, .. }
            | Event::RegionMarked { author, .. }
            | Event::RegionUnmarked { author, .. }
            | Event::RegionBaseline { author, .. }
            | Event::SubRegionHead { author, .. }
            | Event::RegionDrainSet { author, .. }
            | Event::NodeMovedOut { author, .. }
            | Event::ChunkManifestRecorded { author, .. }
            | Event::NodePurged { author, .. }
            | Event::FolderBound { author, .. }
            | Event::FolderUnbound { author, .. }
            | Event::FolderUnboundRoot { author, .. }
            | Event::AclSet { author, .. }
            | Event::MemberTagged { author, .. }
            | Event::SecureBlobUpdated { author, .. } => author,
            Event::NodeCreated(n) => &n.author,
            Event::LinkCreated(l) => &l.author,
            Event::NodeMovedIn { link, .. } => &link.author,
            Event::LinkRemoved { removed_by, .. } | Event::FileLocationRemoved { removed_by, .. } => {
                removed_by
            }
            // D72: we cannot name the author of a kind we cannot parse. An
            // empty author authorizes nothing, which is the right answer —
            // the replay must not grant it authority it cannot verify.
            Event::Unknown { .. } => &[],
        }
    }

    /// Attach an author signature to an as-yet-unsigned event (member-write
    /// commit, doc 07 §5). Only the member-signable kinds are handled; genesis
    /// and device-certificate events are root-signed and never go this path.
    pub fn set_author_sig(&mut self, sig: Vec<u8>) {
        match self {
            Event::NodeCreated(n) => n.sig = sig,
            Event::LinkCreated(l) => l.sig = sig,
            Event::NodeMovedIn { link, .. } => link.sig = sig,
            Event::AclSet { sig: s, .. }
            | Event::MemberTagged { sig: s, .. }
            | Event::SecureBlobUpdated { sig: s, .. }
            | Event::DeviceAuthorized { sig: s, .. }
            | Event::DeviceRevoked { sig: s, .. }
            | Event::RootRotated { sig: s, .. }
            | Event::RecoveryKeyRegistered { sig: s, .. }
            | Event::RecoveryKeyRevoked { sig: s, .. }
            | Event::CertificatesBound { sig: s, .. }
            | Event::FileLocationAdded { sig: s, .. }
            | Event::RegionMarked { sig: s, .. }
            | Event::RegionUnmarked { sig: s, .. }
            | Event::RegionBaseline { sig: s, .. }
            | Event::SubRegionHead { sig: s, .. }
            | Event::RegionDrainSet { sig: s, .. }
            | Event::NodeMovedOut { sig: s, .. }
            | Event::ChunkManifestRecorded { sig: s, .. }
            | Event::LinkReordered { sig: s, .. }
            // P10.0: a member-signed hash-fill successor supersedes the old
            // home link (doc 23 §9.4) — before that only the owner path
            // authored this kind, pre-signed.
            | Event::LinkSuperseded { sig: s, .. }
            // D124 item 7: purge and quality are routed writes now, so a
            // member's signature lands on them here like every other kind.
            | Event::NodePurged { sig: s, .. }
            | Event::MediaQuality { sig: s, .. }
            | Event::LinkRemoved { removal_sig: s, .. }
            | Event::FileLocationRemoved { removal_sig: s, .. } => *s = sig,
            _ => {}
        }
    }

    pub fn encode_body(&self) -> Vec<u8> {
        // D72: an unknown event round-trips its ORIGINAL bytes exactly. Any
        // re-encoding would change the chain hash and break the log for
        // everyone who does understand it.
        if let Event::Unknown { body, .. } = self {
            return body.clone();
        }
        let mut e = Enc::new();
        match self {
            // handled by the byte-exact early return above
            Event::Unknown { .. } => unreachable!("Unknown re-encodes its original bytes"),
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
            Event::CertificatesBound { at, author, sig } => {
                e.u64(*at).bytes(author).bytes(sig);
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
            Event::LinkRelabeled {
                link_id,
                label,
                author,
                sig,
            } => {
                e.string(link_id).string(label).bytes(author).bytes(sig);
            }
            Event::MediaQuality {
                node_id,
                quality,
                source,
                author,
                sig,
            } => {
                e.string(node_id)
                    .string(quality)
                    .string(source)
                    .bytes(author)
                    .bytes(sig);
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
            Event::RegionMarked {
                node_id,
                marked_at,
                kind,
                author,
                sig,
            } => {
                e.string(node_id).u64(*marked_at).bytes(author).bytes(sig);
                if !kind.is_empty() {
                    e.string(kind);
                }
            }
            Event::RegionUnmarked {
                node_id,
                unmarked_at,
                author,
                sig,
            } => {
                e.string(node_id).u64(*unmarked_at).bytes(author).bytes(sig);
            }
            Event::RegionBaseline {
                node_id,
                state_root,
                at,
                author,
                sig,
            } => {
                e.string(node_id).bytes(state_root).u64(*at).bytes(author).bytes(sig);
            }
            Event::RegionDrainSet {
                node_id,
                drains,
                at,
                author,
                sig,
            } => {
                e.string(node_id).u64(*drains as u64).u64(*at).bytes(author).bytes(sig);
            }
            Event::SubRegionHead {
                node_id,
                head_seq,
                head_hash,
                at,
                author,
                sig,
            } => {
                e.string(node_id)
                    .u64(*head_seq)
                    .bytes(head_hash)
                    .u64(*at)
                    .bytes(author)
                    .bytes(sig);
            }
            Event::NodeMovedOut {
                node_id,
                link_id,
                removed_at,
                dest_region,
                dest_head_seq,
                dest_head_hash,
                author,
                sig,
            } => {
                e.string(node_id)
                    .string(link_id)
                    .u64(*removed_at)
                    .string(dest_region)
                    .u64(*dest_head_seq)
                    .bytes(dest_head_hash)
                    .bytes(author)
                    .bytes(sig);
            }
            Event::NodeMovedIn {
                link: l,
                removed_link_id,
                removed_at,
                src_region,
                src_head_seq,
                src_head_hash,
            } => {
                e.string(&l.id)
                    .opt_string(l.parent_id.as_deref())
                    .string(&l.child_id)
                    .string(&l.link_type)
                    .u64(l.link_nonce)
                    .string(&l.order_key)
                    .u64(l.created_at)
                    .bytes(&l.author)
                    .bytes(&l.sig)
                    .string(removed_link_id)
                    .u64(*removed_at)
                    .string(src_region)
                    .u64(*src_head_seq)
                    .bytes(src_head_hash);
            }
            Event::ChunkManifestRecorded {
                file_id,
                content_hash,
                chunk_size,
                manifest_root,
                at,
                author,
                sig,
            } => {
                e.string(file_id)
                    .string(content_hash)
                    .u64(*chunk_size)
                    .bytes(manifest_root)
                    .u64(*at)
                    .bytes(author)
                    .bytes(sig);
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
            Event::FolderUnboundRoot {
                folder_id,
                source_uri,
                unbound_at,
                author,
                sig,
            } => {
                e.string(folder_id)
                    .string(source_uri)
                    .u64(*unbound_at)
                    .bytes(author)
                    .bytes(sig);
            }
            Event::AclSet {
                node_id,
                principal_kind,
                principal_id,
                rights,
                set_at,
                expires_at,
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
                // Trailing, only when set: the canonical no-expiry body stays
                // byte-identical to 1.0 and old bodies decode unchanged.
                if *expires_at != 0 {
                    e.u64(*expires_at);
                }
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
            K_CERTS_BOUND => Event::CertificatesBound {
                at: d.u64()?,
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
            K_LINK_RELABELED => Event::LinkRelabeled {
                link_id: d.string()?,
                label: d.string()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_MEDIA_QUALITY => Event::MediaQuality {
                node_id: d.string()?,
                quality: d.string()?,
                source: d.string()?,
                author: d.bytes()?,
                sig: d.bytes()?,
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
            K_REGION_MARKED => {
                let node_id = d.string()?;
                let marked_at = d.u64()?;
                let author = d.bytes()?;
                let sig = d.bytes()?;
                // Optional trailing kind (D125): absent on pre-D125 bodies. The
                // canonical encoding omits an empty kind, so a present "" is
                // malformed — the AclSet expires_at rule.
                let kind = if d.remaining() > 0 {
                    let k = d.string()?;
                    if k.is_empty() {
                        return Err(PvfsError::Encoding {
                            what: "event body".into(),
                            offset: body.len(),
                            detail: "non-canonical RegionMarked: an empty kind must be omitted".into(),
                        });
                    }
                    k
                } else {
                    String::new()
                };
                Event::RegionMarked {
                    node_id,
                    marked_at,
                    kind,
                    author,
                    sig,
                }
            }
            K_REGION_UNMARKED => Event::RegionUnmarked {
                node_id: d.string()?,
                unmarked_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_REGION_BASELINE => Event::RegionBaseline {
                node_id: d.string()?,
                state_root: d.bytes()?,
                at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_REGION_DRAIN_SET => Event::RegionDrainSet {
                node_id: d.string()?,
                drains: d.u64()? != 0,
                at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_SUB_REGION_HEAD => Event::SubRegionHead {
                node_id: d.string()?,
                head_seq: d.u64()?,
                head_hash: d.bytes()?,
                at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_NODE_MOVED_OUT => Event::NodeMovedOut {
                node_id: d.string()?,
                link_id: d.string()?,
                removed_at: d.u64()?,
                dest_region: d.string()?,
                dest_head_seq: d.u64()?,
                dest_head_hash: d.bytes()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_NODE_MOVED_IN => Event::NodeMovedIn {
                link: Link {
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
                },
                removed_link_id: d.string()?,
                removed_at: d.u64()?,
                src_region: d.string()?,
                src_head_seq: d.u64()?,
                src_head_hash: d.bytes()?,
            },
            K_CHUNK_MANIFEST_RECORDED => Event::ChunkManifestRecorded {
                file_id: d.string()?,
                content_hash: d.string()?,
                chunk_size: d.u64()?,
                manifest_root: d.bytes()?,
                at: d.u64()?,
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
            K_FOLDER_UNBOUND_ROOT => Event::FolderUnboundRoot {
                folder_id: d.string()?,
                source_uri: d.string()?,
                unbound_at: d.u64()?,
                author: d.bytes()?,
                sig: d.bytes()?,
            },
            K_ACL_SET => {
                let node_id = d.string()?;
                let principal_kind = d.u64()?;
                let principal_id = d.bytes()?;
                let rights = d.u64()?;
                let set_at = d.u64()?;
                let author = d.bytes()?;
                let sig = d.bytes()?;
                // Optional trailing expiry (1.1): absent on pre-1.1 bodies. The
                // canonical encoding omits a zero, so a present 0 is malformed.
                let expires_at = if d.remaining() > 0 {
                    match d.u64()? {
                        0 => {
                            return Err(PvfsError::Encoding {
                                what: "event body".into(),
                                offset: body.len() - 8,
                                detail: "non-canonical AclSet: expires_at 0 must be omitted".into(),
                            })
                        }
                        t => t,
                    }
                } else {
                    0
                };
                Event::AclSet {
                    node_id,
                    principal_kind,
                    principal_id,
                    rights,
                    set_at,
                    expires_at,
                    author,
                    sig,
                }
            }
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
            // D72 Part A — forward compatibility. A kind this binary does not
            // know is KEPT, not rejected: a newer box must be able to write
            // one and have an older box still replay the log. The chain hash
            // covers the raw bytes, so integrity survives ignorance.
            other => {
                return Ok(Event::Unknown {
                    kind: other.to_string(),
                    body: body.to_vec(),
                })
            }
        };
        // Trailing bytes are TOLERATED (D72 Part A), where they used to be a
        // hard error. That is what lets a future version append an optional
        // field to an existing event without breaking every older reader —
        // the single change that turns a fleet-wide upgrade into a rolling
        // one.
        //
        // What is given up: canonical encoding, i.e. exactly one byte string
        // per event. The signature still authenticates the DECODED fields, so
        // padding cannot forge meaning; and the chain hash covers the raw
        // bytes, so padding cannot hide either. It only means an authorized
        // writer could emit a non-minimal encoding of an event it was already
        // entitled to write.
        let _trailing = d.remaining();
        Ok(ev)
    }

    /// Verify the event's own signature(s) — used on replay/sync (spec §6).
    /// PVOS D192: `ctx` is the forest the event sits in — a forest-authority
    /// event must be signed for it (v2), or, only while it is not bound, in
    /// the older form without a forest (v1).
    pub fn verify_sig(&self, ctx: &SigContext<'_>) -> Result<()> {
        // D72: an event we cannot parse cannot have its signature checked —
        // we do not know which bytes were signed. Report that honestly
        // instead of returning Ok, which would be a silent "verified".
        // Callers decide what to do with a forest they only partly understand
        // (§5.A.3); they must not be told it verified.
        if let Event::Unknown { kind, .. } = self {
            return Err(PvfsError::Encoding {
                what: "event signature".into(),
                offset: 0,
                detail: format!(
                    "cannot verify {kind:?}: this binary does not know the kind, so it \
                     cannot know what was signed — upgrade this box to fold it"
                ),
            });
        }
        match self {
            // handled by the honest refusal above
            Event::Unknown { .. } => unreachable!("Unknown refuses verification above"),
            Event::ForestCreated {
                instance_id,
                forest_id,
                root_node_id,
                created_at,
                author,
                sig,
            } => {
                // Genesis: born bound (v2) or not (v1) — either verifies;
                // `genesis_born_bound` says which.
                let digest = |bound| msg_forest_created(instance_id, forest_id, root_node_id, *created_at, author, bound);
                crypto::verify_digest(author, &digest(true), sig)
                    .or_else(|_| crypto::verify_digest(author, &digest(false), sig))
            }
            Event::DeviceAuthorized {
                device_pubkey,
                device_index,
                authorized_at,
                author,
                sig,
            } => verify_authority(ctx, author, sig, |f| {
                msg_device_authorized(f, device_pubkey, *device_index, *authorized_at, author)
            }),
            Event::DeviceRevoked {
                device_pubkey,
                revoked_at,
                author,
                sig,
            } => verify_authority(ctx, author, sig, |f| msg_device_revoked(f, device_pubkey, *revoked_at, author)),
            Event::RootRotated {
                new_root_pubkey,
                rotated_at,
                author,
                sig,
            } => verify_authority(ctx, author, sig, |f| msg_root_rotated(f, new_root_pubkey, *rotated_at, author)),
            Event::RecoveryKeyRegistered {
                recovery_pubkey,
                registered_at,
                author,
                sig,
            } => verify_authority(ctx, author, sig, |f| {
                msg_recovery_key_registered(f, recovery_pubkey, *registered_at, author)
            }),
            Event::RecoveryKeyRevoked {
                recovery_pubkey,
                revoked_at,
                author,
                sig,
            } => verify_authority(ctx, author, sig, |f| {
                msg_recovery_key_revoked(f, recovery_pubkey, *revoked_at, author)
            }),
            Event::CertificatesBound { at, author, sig } => {
                crypto::verify_digest(author, &msg_certs_bound(ctx.forest_id, *at, author), sig)
            }
            Event::NodeCreated(n) => n.verify(),
            Event::LinkCreated(l) => l.verify(),
            Event::NodeMovedIn { link, .. } => link.verify(),
            Event::ChunkManifestRecorded {
                file_id,
                content_hash,
                chunk_size,
                manifest_root,
                at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_chunk_manifest_recorded(
                    file_id,
                    content_hash,
                    *chunk_size,
                    manifest_root,
                    *at,
                    author,
                ),
                sig,
            ),
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
            Event::LinkRelabeled {
                link_id,
                label,
                author,
                sig,
            } => crypto::verify_digest(author, &msg_link_relabeled(link_id, label, author), sig),
            Event::MediaQuality {
                node_id,
                quality,
                source,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_media_quality(node_id, quality, source, author),
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
            Event::RegionMarked {
                node_id,
                marked_at,
                kind,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_region_marked(node_id, *marked_at, kind, author),
                sig,
            ),
            Event::RegionUnmarked {
                node_id,
                unmarked_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_region_unmarked(node_id, *unmarked_at, author),
                sig,
            ),
            Event::RegionBaseline {
                node_id,
                state_root,
                at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_region_baseline(node_id, state_root, *at, author),
                sig,
            ),
            Event::RegionDrainSet {
                node_id,
                drains,
                at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_region_drain_set(node_id, *drains, *at, author),
                sig,
            ),
            Event::SubRegionHead {
                node_id,
                head_seq,
                head_hash,
                at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_sub_region_head(node_id, *head_seq, head_hash, *at, author),
                sig,
            ),
            Event::NodeMovedOut {
                node_id,
                link_id,
                removed_at,
                dest_region,
                dest_head_seq,
                dest_head_hash,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_node_moved_out(
                    node_id,
                    link_id,
                    *removed_at,
                    dest_region,
                    *dest_head_seq,
                    dest_head_hash,
                    author,
                ),
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
            Event::FolderUnboundRoot {
                folder_id,
                source_uri,
                unbound_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_folder_unbound_root(folder_id, source_uri, *unbound_at, author),
                sig,
            ),
            Event::AclSet {
                node_id,
                principal_kind,
                principal_id,
                rights,
                set_at,
                expires_at,
                author,
                sig,
            } => crypto::verify_digest(
                author,
                &msg_acl_set(
                    node_id,
                    *principal_kind,
                    principal_id,
                    *rights,
                    *set_at,
                    *expires_at,
                    author,
                ),
                sig,
            ),
            Event::MemberTagged {
                member_pubkey,
                tag,
                granted,
                set_at,
                author,
                sig,
            } => verify_authority(ctx, author, sig, |f| {
                msg_member_tagged(f, member_pubkey, tag, *granted, *set_at, author)
            }),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    fn signer() -> (identity::SigningKey, Vec<u8>) {
        let k = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
        let pk = crypto::pubkey_bytes(&k);
        (k, pk)
    }

    fn unbound() -> SigContext<'static> {
        SigContext { forest_id: "forest-a", bound: false }
    }

    /// A device certificate from `key`, signed for `forest` (v2) or, with
    /// `None`, in the older form (v1).
    fn device_cert(key: &identity::SigningKey, author: &[u8], forest: Option<&str>) -> Event {
        let device = crypto::pubkey_bytes(&identity::generate_device_key());
        let sig = crypto::sign_digest(key, &msg_device_authorized(forest, &device, 5, 1_000, author)).unwrap();
        Event::DeviceAuthorized {
            device_pubkey: device,
            device_index: 5,
            authorized_at: 1_000,
            author: author.to_vec(),
            sig,
        }
    }

    // PVOS D192 — the forest id is in the v2 digest: one certificate, one forest.
    #[test]
    fn a_v2_certificate_names_its_forest() {
        let (d, a) = (b"device", b"author");
        let v1 = msg_device_authorized(None, d, 1, 2, a);
        let in_a = msg_device_authorized(Some("forest-a"), d, 1, 2, a);
        let in_b = msg_device_authorized(Some("forest-b"), d, 1, 2, a);
        assert_ne!(v1, in_a);
        assert_ne!(in_a, in_b);
        // every family member differs by forest
        assert_ne!(msg_root_rotated(Some("forest-a"), d, 1, a), msg_root_rotated(Some("forest-b"), d, 1, a));
        assert_ne!(msg_device_revoked(Some("forest-a"), d, 1, a), msg_device_revoked(None, d, 1, a));
        assert_ne!(
            msg_member_tagged(Some("forest-a"), d, "admin", true, 1, a),
            msg_member_tagged(Some("forest-b"), d, "admin", true, 1, a)
        );
        assert_ne!(
            msg_recovery_key_registered(Some("forest-a"), d, 1, a),
            msg_recovery_key_registered(None, d, 1, a)
        );
        assert_ne!(msg_recovery_key_revoked(Some("forest-a"), d, 1, a), msg_recovery_key_revoked(None, d, 1, a));
    }

    #[test]
    fn a_certificate_verifies_only_in_its_own_forest_and_v1_only_while_unbound() {
        let (key, author) = signer();
        let bound_a = SigContext { forest_id: "forest-a", bound: true };
        let unbound_a = SigContext { forest_id: "forest-a", bound: false };
        let bound_b = SigContext { forest_id: "forest-b", bound: true };
        let unbound_b = SigContext { forest_id: "forest-b", bound: false };

        let for_a = device_cert(&key, &author, Some("forest-a"));
        for_a.verify_sig(&bound_a).expect("signed for forest-a: valid there");
        for_a.verify_sig(&unbound_a).expect("a v2 certificate is valid before the binding too");
        assert!(for_a.verify_sig(&bound_b).is_err(), "never in another forest — the replay");
        assert!(for_a.verify_sig(&unbound_b).is_err(), "not even one that is not bound yet");

        let old = device_cert(&key, &author, None);
        old.verify_sig(&unbound_a).expect("v1: valid while the forest is not bound");
        let err = old.verify_sig(&bound_a).unwrap_err().to_string();
        assert!(err.contains("forest-a"), "{err}");
    }

    #[test]
    fn the_binding_and_a_bound_genesis_verify_for_their_forest() {
        let (key, author) = signer();
        let sig = crypto::sign_digest(&key, &msg_certs_bound("forest-a", 7, &author)).unwrap();
        let ev = Event::CertificatesBound { at: 7, author: author.clone(), sig };
        let back = Event::decode(K_CERTS_BOUND, &ev.encode_body()).unwrap();
        assert_eq!(back, ev);
        assert_eq!(back.kind(), K_CERTS_BOUND);
        assert_eq!(back.author(), author.as_slice());
        back.verify_sig(&unbound()).unwrap();
        assert!(back.verify_sig(&SigContext { forest_id: "forest-b", bound: false }).is_err());

        let genesis = |born_bound| {
            let sig = crypto::sign_digest(&key, &msg_forest_created("i", "forest-a", "r", 9, &author, born_bound)).unwrap();
            Event::ForestCreated {
                instance_id: "i".into(),
                forest_id: "forest-a".into(),
                root_node_id: "r".into(),
                created_at: 9,
                author: author.clone(),
                sig,
            }
        };
        let (born, old) = (genesis(true), genesis(false));
        born.verify_sig(&unbound()).unwrap();
        old.verify_sig(&unbound()).unwrap();
        assert!(born.genesis_born_bound());
        assert!(!old.genesis_born_bound());
        assert!(!back.genesis_born_bound());
    }

    fn acl_set(expires_at: u64) -> Event {
        let (key, author) = signer();
        let (node, kind, id, rights, t) = ("n".repeat(64), 1u64, author.clone(), 3u64, 1_000u64);
        let sig = crypto::sign_digest(
            &key,
            &msg_acl_set(&node, kind, &id, rights, t, expires_at, &author),
        )
        .unwrap();
        Event::AclSet {
            node_id: node,
            principal_kind: kind,
            principal_id: id,
            rights,
            set_at: t,
            expires_at,
            author,
            sig,
        }
    }

    // doc 13 Q-E1 wire compat: a no-expiry AclSet is byte-identical to its 1.0
    // encoding (expiry omitted), so pre-1.1 bodies decode and old sigs verify.
    #[test]
    fn aclset_without_expiry_matches_v1_bytes_and_verifies() {
        let ev = acl_set(0);
        let body = ev.encode_body();
        let Event::AclSet {
            node_id,
            principal_kind,
            principal_id,
            rights,
            set_at,
            author,
            sig,
            ..
        } = &ev
        else {
            unreachable!()
        };
        // the exact 1.0 field sequence — no trailing expiry
        let mut v1 = Enc::new();
        v1.string(node_id)
            .u64(*principal_kind)
            .bytes(principal_id)
            .u64(*rights)
            .u64(*set_at)
            .bytes(author)
            .bytes(sig);
        assert_eq!(body, v1.finish(), "no-expiry AclSet must stay 1.0-identical");

        let back = Event::decode(K_ACL_SET, &body).unwrap();
        assert_eq!(back, ev);
        back.verify_sig(&unbound()).unwrap();
    }

    #[test]
    fn aclset_with_expiry_roundtrips_and_verifies() {
        let ev = acl_set(2_000);
        let body = ev.encode_body();
        let back = Event::decode(K_ACL_SET, &body).unwrap();
        assert_eq!(back, ev);
        back.verify_sig(&unbound()).unwrap();
        assert!(matches!(back, Event::AclSet { expires_at: 2_000, .. }));
    }

    // The v2 digest domain covers the expiry: same fields, different expiry (or
    // none) can never share a signature.
    #[test]
    fn aclset_expiry_changes_the_signed_digest() {
        let a = msg_acl_set("n", 1, b"p", 3, 1_000, 0, b"a");
        let b = msg_acl_set("n", 1, b"p", 3, 1_000, 2_000, b"a");
        let c = msg_acl_set("n", 1, b"p", 3, 1_000, 3_000, b"a");
        assert_ne!(a, b);
        assert_ne!(b, c);
    }

    // Canonical form omits a zero expiry — a present 0 must be rejected, so one
    // logical event keeps exactly one valid byte sequence (spec §3).
    #[test]
    fn aclset_trailing_zero_expiry_is_non_canonical() {
        let ev = acl_set(0);
        let mut body = ev.encode_body();
        body.extend_from_slice(&0u64.to_le_bytes());
        let err = Event::decode(K_ACL_SET, &body);
        assert!(
            matches!(err, Err(PvfsError::Encoding { .. })),
            "expected Encoding error, got {err:?}"
        );
    }
}
