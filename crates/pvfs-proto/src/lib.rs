//! PVFS daemon/client wire protocol (doc 07).
//!
//! - Transport: length-prefixed frames.
//!   - JSON control frames: `u32 LE length || JSON body`
//!   - Binary data frames: `u32 LE length || raw bytes`  (used only for `Cat` data plane)
//!     The frame format is identical; the receiver switches to `read_data_frame` after a
//!     `CatStart` JSON message and back to `read_msg` after `CatDone`.
//! - Auth: challenge-response — the daemon sends a nonce, the client signs
//!   [`auth_digest`] with its identity key; the proven key is the principal.
//! - Messages: [`ServerMsg`] / [`ClientMsg`].

use std::io::{self, Read, Write};

use pvfs_core::crypto;
use pvfs_core::encoding::Enc;
use serde::{Deserialize, Serialize};

/// Bumped when the wire format changes incompatibly.
/// The wire protocol version, sent in every connect `Challenge`. RULE:
/// bump this in the SAME commit as any additive wire op, so a consumer can
/// require "protocol ≥ N" and a mismatched daemon is caught at the launch
/// boundary instead of closing the connection mid-op (PVOS D63; the ingest
/// ops shipped at 3 without a bump and it cost a live pass).
///   2 → 3: the P10 external-ingest ops (IngestBegin/Write/Verified/
///          Commit/Abort/List), ranged `Cat`, and P10.2 partial paths.
///   4 → 5: D125 `CommitRegionHead` — a region owner publishes its catalogue
///          head through the forest owner. Additive; compatible-with stays.
///   5 → 6: D124 `Purge` and `SetQuality` — the two CLI commands that did not
///          route on a replica. Additive; compatible-with stays.
pub const PROTO_VERSION: u32 = 6;

/// The oldest proto this binary can still talk to (D73).
///
/// PROTO_VERSION says what we speak; this says how far back we degrade. Every
/// change between the two has been additive and gated, so a peer anywhere in
/// `[PROTO_COMPATIBLE_WITH, PROTO_VERSION]` is safe to roll against — which is
/// what lets `upgrade.yml` allow a proto bump instead of refusing every one.
///
/// Moving THIS number is the fleet-wide event that a bare `PROTO_VERSION` bump
/// used to be.
pub const PROTO_COMPATIBLE_WITH: u32 = 3;

/// A binary cannot degrade to a proto newer than it speaks. Enforced at COMPILE
/// time so the pair can never ship inconsistent.
const _: () = assert!(PROTO_COMPATIBLE_WITH <= PROTO_VERSION);
/// Hard cap on a single control frame (bulk bytes use the data plane, not frames).
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;
/// Chunk size for binary data-plane frames (1 MiB).
pub const DATA_CHUNK: usize = 1 << 20;

/// Server → client messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Sent immediately on connect. The client signs `auth_digest(nonce, forest_id, expiry_ms)`.
    Challenge {
        nonce: String, // hex
        forest_id: String,
        expiry_ms: u64,
        version: u32,
    },
    /// Auth resolved; `principal` is the human form ("public" or "key:<hex>").
    Ready { principal: String },
    Info {
        instance_id: String,
        forest_id: String,
        root: String,
    },
    Ls { children: Vec<ChildInfo> },
    Stat { node: NodeInfo },
    /// A node's inline payload (hex; response to `ClientMsg::Payload`).
    Payload { payload: String },
    /// Phase 1 of a write: the digests to sign (hex), plus the id the write yields.
    Prepared {
        prepared_id: String,
        preimages: Vec<String>,
        result_id: String,
    },
    /// Phase 2 result: the committed write's id.
    Committed { id: String },
    /// Data-plane cat: announces the file size; raw binary data frames follow.
    CatStart { size: u64 },
    /// Data-plane cat: all bytes sent; total written byte count.
    CatDone { written: u64 },
    /// The log's chain tip position (response to `ClientMsg::LogInfo`; F2).
    LogInfo { tip_seq: u64 },
    /// A batch of raw signed log rows (response to `ClientMsg::LogRead`; F2).
    /// `tip_seq` is the tip at read time so the client knows when it's caught up.
    LogEvents {
        tip_seq: u64,
        events: Vec<LogEventWire>,
    },
    /// A typed failure; `code` mirrors a `PvfsError` family.
    Error { code: String, message: String },
    /// P9 (doc 22): the chunk manifest for a file this holder can read —
    /// `hashes[i]` is the hex BLAKE3 of bytes `[i*chunk_size, ...)`.
    ChunkManifest {
        size: u64,
        chunk_size: u64,
        hashes: Vec<String>,
    },
    /// The job runner's live state (response to `ClientMsg::ServeStatus`; P5).
    /// `runner` is `"on"` when a runner thread is attached, `"off"` when this
    /// daemon predates jobs or was started without one.
    ServeJobs {
        runner: String,
        jobs: Vec<ServeJobWire>,
        /// D127 (doc 26 §7.5): conflicting paths in the merged view this box
        /// holds — the in-band signal nobody has to remember to ask for.
        /// Absent on pre-D127 daemons, so defaulted rather than a proto bump.
        #[serde(default)]
        conflicts: u64,
    },
    /// P10.0 (doc 23 §3): phase 1 of `IngestBegin` — the session layout plus
    /// the standard prepared-write fields. The client signs the preimages and
    /// sends the usual `Commit`; the session activates when that commit
    /// lands. Boxed so the enum stays small; the wire JSON is unchanged
    /// (internal tagging flattens the newtype).
    IngestPrepared(Box<IngestPreparedWire>),
    /// P10.0: an `IngestWrite` upload landed (bytes received this call).
    IngestWritten { bytes: u64 },
    /// P10.0: per-file verification progress after an `IngestVerified`.
    IngestProgress {
        bytes_verified: u64,
        chunks_done: u64,
        chunks_total: u64,
    },
    /// P10.0: the live ingest sessions (response to `ClientMsg::IngestList`).
    IngestSessions { sessions: Vec<IngestSessionWire> },
}

/// Phase-1 answer to `IngestBegin` (P10.0): the session layout plus the
/// standard prepared-write fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestPreparedWire {
    pub session: String,
    /// The subtree root: the torrent folder, or the file itself for a
    /// single bare file.
    pub root: String,
    /// The `pvos.download` origin record's node id.
    pub origin: String,
    pub files: Vec<IngestFileWire>,
    pub prepared_id: String,
    pub preimages: Vec<String>,
    pub result_id: String,
}

/// One in-flight ingest file (P10.0, doc 23 §3): the catalog pointer node,
/// its declared size, verification progress, and — once committed — the
/// hash-fill successor's id (commits re-identify nodes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestFileWire {
    pub node: String,
    pub rel_path: String,
    pub size: u64,
    #[serde(default)]
    pub bytes_verified: u64,
    #[serde(default)]
    pub chunks_done: u64,
    #[serde(default)]
    pub chunks_total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed: Option<String>,
    /// P10.1 (doc 23 §8.1): byte ranges readers are currently blocked on —
    /// the demand signal the app maps to sequential piece priority.
    /// Additive: absent on the wire when empty, so P10.0 peers interop.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hot: Vec<(u64, u64)>,
    /// P10.2 (doc 23 §13): the file's ingest partial path — the same-box
    /// fast path. Filled only on Unix-socket connections (a TCP caller
    /// gets `None`; server paths are useless and leaky off-box). A direct
    /// writer creates sparse, writes at offsets, and reports ranges via
    /// `IngestVerified` as usual. Additive: absent for older peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_path: Option<String>,
}

/// One ingest session (P10.0): identity plus per-file state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestSessionWire {
    pub session: String,
    pub root: String,
    pub origin: String,
    pub files: Vec<IngestFileWire>,
}

/// One declared file in an `IngestBegin` (P10.0): its path inside the
/// torrent (folders created as needed) and the metainfo size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestFileSpecWire {
    pub rel_path: String,
    pub size: u64,
}

/// One serve job's live state (P5, doc 18 §2): configured name, whether
/// `serve.jobs` enables it, what the runner last did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServeJobWire {
    pub name: String,
    pub enabled: bool,
    /// `"idle"` | `"running"` | `"backoff"` | `"disabled"` (P5.0 runners report
    /// `"idle"` for enabled jobs — bodies land per phase, doc 18 §5).
    pub state: String,
    /// Unix ms of the last successful run, if any.
    pub last_ok_ms: Option<u64>,
    /// The last failure message, cleared by the next success.
    pub last_error: Option<String>,
}

/// One shipped log row, verbatim (F2 log shipping, doc 17 §5): the replica
/// re-verifies the chain linkage on ingest and the full log (signatures +
/// replay authorization) on open, so these carry no authority of their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEventWire {
    pub seq: u64,
    pub kind: String,
    pub body: String,       // hex
    pub chain_hash: String, // hex
    pub written_at: u64,
}

/// A high-level write intent the daemon turns into signable events (doc 07 §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WriteOp {
    /// Create a folder named `label` under `parent`.
    Mkdir { parent: String, label: String },
    /// Create a **secure** node (doc 12) named `label` under `parent`. Its
    /// ciphertext location is managed — allocated on the first `SecurePut` — so
    /// an app provisions storage on the fly without ever choosing a path.
    SecureCreate { parent: String, label: String },
    /// Create a file node named `label` under `parent` (metadata only; bytes are
    /// recorded separately by a location).
    AddFile {
        parent: String,
        label: String,
        size: u64,
        mime: String,
        /// D84 — the content hash, computed BY THE BOX THAT HOLDS THE BYTES.
        ///
        /// Hashing has to happen where the bytes are, and on this fleet that is
        /// never the owner: it holds the log and no media. Without this field a
        /// replica computed the hash during `on_add` ingest and then threw it
        /// away, because the write-through op had nowhere to put it — so 99.9%
        /// of the library is unhashed and the swarm, which needs a content hash
        /// as its trust anchor, cannot run.
        ///
        /// `default` keeps this additive: an older client omits it and gets the
        /// previous behaviour, an unhashed pointer node.
        #[serde(default)]
        content_hash: String,
    },
    /// D85 — fill a lazy content hash, computed BY THE BOX THAT HOLDS THE
    /// BYTES. Mints the successor node the hash implies and carries the home
    /// link and every location across, as one write.
    ///
    /// The owner cannot do this itself: it holds the log and none of the media.
    SetContentHash {
        node: String,
        content_hash: String,
        size_bytes: u64,
    },
    /// Create a typed node with an inline **payload** (hex; capped small). The
    /// payload lives in the signed event log itself — for small, auditable,
    /// replayable records (e.g. PVOS grant events, doc 13). Not for file bytes
    /// (`AddFile` + locations) or large/private blobs (`SecureCreate`/`SecurePut`).
    AddNode {
        parent: String,
        label: String,
        node_type: String,
        payload: String, // hex
    },
    /// Unlink `node` from its home parent (soft remove).
    Rm { node: String },
    /// Record where a file node's bytes live.
    AddLocation { file: String, uri: String },
    /// Retract a recorded location (P6.0, doc 19 §2). Write on the file.
    RemoveLocation { file: String, uri: String },
    /// Create a link `parent → child` (P6.0). Write on the parent; the
    /// `contains` one-home/cycle rules apply exactly as locally. `order_key`
    /// empty = append after the last sibling.
    Link {
        parent: String,
        child: String,
        link_type: String,
        #[serde(default)]
        order_key: String,
    },
    /// Soft-remove a link (P6.0). Write on the link's parent.
    Unlink { link_id: String },
    /// Change a link's sibling order (P6.0). Write on the link's parent.
    Reorder { link_id: String, key: String },
    /// D73/proto 4 — set a link's display label (D72). Write on the link's
    /// parent, exactly like `Reorder`: both change a MUTABLE attribute of an
    /// edge without touching the edge's identity.
    ///
    /// Additive and GATED: a client sends this only when the daemon reports
    /// proto >= 4, and falls back to the pre-D72 successor-node path otherwise.
    /// That is what makes it rollable — an older daemon never has to know it
    /// exists, and now refuses it legibly rather than dropping the connection.
    Relabel { link_id: String, label: String },
    /// Re-home `node` under `new_parent`.
    Mv { node: String, new_parent: String },
    /// Set a principal's rights on a node. `principal` = `public`|`any`|`tag:<name>`|
    /// `key:<hex>`; `rights` = `rwa` letters or `-` to clear. `expires_at` (doc 13
    /// Q-E1, 1.1): ms epoch after which the grant is inert; 0 = never. Defaulted
    /// so a pre-1.1 client's frame still parses (additive wire change).
    SetAcl {
        node: String,
        principal: String,
        rights: String,
        #[serde(default)]
        expires_at: u64,
    },
    /// Grant (`granted`) or remove a membership tag from a member key (hex).
    TagMember {
        member: String,
        tag: String,
        granted: bool,
    },
    /// Admit a member's key (hex).
    AuthorizeMember { pubkey: String },
    /// Revoke a device/member key (hex).
    Revoke { pubkey: String },
    /// D125 item 8 — a region owner publishes the head of its catalogue
    /// region: `hash` is the hex blake3 of manifest `seq`. The forest owner
    /// prepares a `SubRegionHead` under the author's admin grant on the
    /// region (`region mark --owner`) and refuses anything else about it.
    CommitRegionHead {
        region: String,
        seq: u64,
        hash: String,
    },
    /// D124 item 7 — purge orphaned nodes (admin on each). A replica used to
    /// call the engine directly and be refused as read-only.
    Purge { ids: Vec<String> },
    /// D124 item 7 — record a D76 quality measurement on a node (write on
    /// it); `quality` is `MediaQuality::encode`, `source` names the measurer.
    SetQuality {
        node: String,
        quality: String,
        source: String,
    },
}

/// Client → server messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Prove possession of `pubkey` via a signature over the challenge digest.
    Auth { pubkey: String, sig: String },
    /// Decline to authenticate → resolved as `public`.
    Anonymous,
    Info,
    Ls { node: String },
    Stat { node: String },
    /// Read a node's inline payload (read-ACL-gated; hex on the wire).
    Payload { node: String },
    /// Stream a file node's bytes. Server responds: CatStart, then binary data
    /// frames (`write_data_frame`), then CatDone. P9 (doc 22): `offset`/`len`
    /// select a byte range — `(0, 0)` (the defaults, absent on the wire) is
    /// the whole file, so old peers interoperate unchanged.
    Cat {
        node: String,
        #[serde(default, skip_serializing_if = "is_zero")]
        offset: u64,
        #[serde(default, skip_serializing_if = "is_zero")]
        len: u64,
    },
    /// P9 (doc 22): the file's chunk manifest — BLAKE3 per 8 MiB chunk,
    /// computed from the holder's bytes (sidecar-cached). UNSIGNED and
    /// advisory: it steers parallel pulls and resume; the catalog hash
    /// remains the trust anchor. Read-gated like `Cat`.
    ChunkManifest { node: String },
    /// Stream a **secure** blob's ciphertext (doc 12 §8), verified against the
    /// signed ledger first. Same wire shape as `Cat` (CatStart → frames → CatDone).
    SecureCat { node: String },
    /// Upload a secure blob's new ciphertext, then advance its ledger. The client
    /// sends this, then binary data frames terminated by a zero-length frame; the
    /// server writes the bytes and replies `Prepared` (the `SecureBlobUpdated`
    /// digest to sign), after which the client `Commit`s as usual.
    SecurePut { node: String },
    /// The log's chain tip (F2). Gated like `LogRead`. P7.2b: `region` scopes
    /// the request to one region **generation** — `""` (the default; absent on
    /// the wire) is the top log, else `<region-root-hex>/g-<host>-<seq>.db`
    /// (the generation's file name, doc 20 §2.3/§2.4). Additive: old peers
    /// serialize/parse the top-log form unchanged.
    LogInfo {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        region: String,
    },
    /// Ship raw log rows `[from_seq ..]`, at most `max` per batch (F2).
    /// Gated: the caller needs **admin rights on the forest root** — a full
    /// log reveals the whole forest's history, so replication is an
    /// owner/admin capability (doc 17 §5), not a member read. P7.2b: a
    /// region-scoped request (see `LogInfo.region`) is instead gated on
    /// admin rights on **that region's root** — a region maps to an
    /// authority, so its holder replicates it without whole-forest rights.
    LogRead {
        from_seq: u64,
        max: u32,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        region: String,
    },
    /// Long-poll `LogRead` (F5.4, doc 17 §7.5): reply immediately when the
    /// tip has reached `from_seq`, else block up to `timeout_ms` (server-
    /// capped) waiting for new events; an empty `LogEvents` means "still
    /// nothing — poll again". Same gate as `LogRead` (region-scoped when
    /// `region` is set).
    LogWait {
        from_seq: u64,
        max: u32,
        timeout_ms: u64,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        region: String,
    },
    /// Phase 1 of a write: ask the daemon to build the signable events for `op`.
    PrepareWrite { op: WriteOp },
    /// Phase 2: return one signature (hex) per preimage, in order.
    Commit {
        prepared_id: String,
        sigs: Vec<String>,
    },
    /// Live job-runner state (P5, doc 18 §2). Answered like `Info` — operational
    /// metadata, no catalog content.
    ServeStatus,
    /// P10.0 (doc 23 §3): open an external-ingest session — catalog the whole
    /// torrent now (unhashed pointer nodes), bytes arrive later. Phase 1 of a
    /// member write: answered `IngestPrepared`; the standard `Commit` lands it
    /// and activates the session. The daemon refuses when the declared total
    /// exceeds free space at the sync store (doc 23 §8.3) unless
    /// `allow_shortfall` accepts the caller's risk.
    IngestBegin {
        parent: String,
        /// Torrent name → the root folder's label. May be empty for a single
        /// bare file (no wrapping folder).
        #[serde(default, skip_serializing_if = "String::is_empty")]
        name: String,
        /// Origin kind for the `pvos.download` record, e.g. `bittorrent`.
        kind: String,
        /// The torrent infohash (hex) — the early-serve trust anchor.
        infohash: String,
        piece_size: u64,
        files: Vec<IngestFileSpecWire>,
        #[serde(default)]
        allow_shortfall: bool,
    },
    /// P10.0: upload bytes into a session file's partial at `offset` — the
    /// `SecurePut` data-plane shape: binary frames follow, a zero-length
    /// frame terminates, the daemon replies `IngestWritten`. Out-of-order
    /// and duplicate writes are fine (the partial is sparse).
    IngestWrite {
        session: String,
        file: String,
        #[serde(default, skip_serializing_if = "is_zero")]
        offset: u64,
    },
    /// P10.0: the app reports byte ranges whose torrent pieces verified
    /// against the infohash. The daemon hashes newly covered chunks into the
    /// progress sidecar and replies `IngestProgress`.
    IngestVerified {
        session: String,
        file: String,
        /// Half-open `[start, end)` byte ranges.
        ranges: Vec<(u64, u64)>,
    },
    /// P10.0: commit one file — whole-file BLAKE3 → hash-fill successor +
    /// attestation (+ the `pvos.download.closed` record if this is the
    /// session's last file), then publish into the store. Phase 1 of a member
    /// write: answered `Prepared`; `Commit` lands it (`Committed.id` is the
    /// successor node — commits re-identify).
    IngestCommit { session: String, file: String },
    /// P10.0: abort the session — a `pvos.download.closed{aborted}` record
    /// (+ unlink of the subtree root unless `keep_catalog`), partials and
    /// progress removed. Phase 1 of a member write: answered `Prepared`.
    IngestAbort {
        session: String,
        #[serde(default)]
        keep_catalog: bool,
    },
    /// P10.0: the live sessions with per-file progress (active-member gated).
    IngestList,
    /// Claim the WRITE LEASE over `roots` and everything beneath them
    /// (PVOS D67 C3). While held, writes under those subtrees are refused
    /// from every OTHER connection — which is what makes "one authority per
    /// served forest" an invariant rather than a convention.
    ///
    /// Per CONNECTION, not per identity: a daemon serving a forest and a CLI
    /// run by its owner authenticate with the SAME key, so identity cannot
    /// separate them. The lease is released when the connection ends — clean
    /// close or crash — so a dead holder never blocks recovery.
    ///
    /// Idempotent for the holder; refused (`forbidden`) when another live
    /// connection already holds an overlapping root.
    ClaimWriteLease { roots: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildInfo {
    pub id: String,
    pub label: String,
    pub node_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub label: String,
    pub node_type: String,
    /// The caller's effective rights on the node, e.g. `"r"` / `"rwa"` / `"-"`.
    pub rights: String,
    /// The node's home (`contains`) parent; `None` for a tree root.
    /// (Additive since 1.0 — defaults for older peers.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// The 32-byte digest a client signs to prove key possession (doc 07 §2). Binds
/// the nonce, the forest id, and an expiry so a signature for one forest/window
/// can't be replayed to another.
pub fn auth_digest(nonce: &[u8], forest_id: &str, expiry_ms: u64) -> [u8; 32] {
    let mut e = Enc::new();
    e.bytes(nonce).string(forest_id).u64(expiry_ms);
    crypto::domain_digest("pvfs:daemon-auth:v1:", &e.finish())
}

/// Write one length-prefixed JSON control frame.
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg).map_err(invalid)?;
    let len = u32::try_from(body.len()).map_err(|_| invalid("frame too large"))?;
    if len > MAX_FRAME {
        return Err(invalid("frame exceeds cap"));
    }
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one length-prefixed JSON control frame; `Ok(None)` on a clean EOF.
/// One frame off the wire: either a message this binary understands, or
/// well-formed JSON it does not.
///
/// D73: the distinction exists because the framing makes it SAFE. Frames are
/// length-prefixed, so a frame we cannot interpret has still been consumed
/// exactly — the stream stays aligned and the next frame is readable. That is
/// what lets an unknown request be REFUSED instead of killing the connection,
/// which is what used to happen and is why no additive wire change could roll.
///
/// Note the asymmetry with the log's `Event::Unknown`, and keep it: an unknown
/// EVENT is *retained*, because the log is a durable shared record and those
/// bytes must survive for boxes that do understand them. An unknown REQUEST is
/// *refused* — there is nothing to preserve, and acting on what you cannot
/// parse is the one thing that must never happen. Tolerance means "do not
/// die", never "proceed anyway".
#[derive(Debug, Clone)]
pub enum Frame<T> {
    Msg(T),
    /// Valid JSON, unknown shape. `tag` is the discriminant if one was present
    /// (`t` for a message, `op` for a write) — so the refusal can name what it
    /// could not do rather than saying only "no".
    Unknown { tag: String },
}

/// Read one frame, tolerating a message this binary does not know.
///
/// Prefer this over [`read_msg`] on any long-lived connection: it is the
/// difference between "this daemon cannot do that" and the peer's connection
/// dropping.
pub fn read_frame<R: Read, T: serde::de::DeserializeOwned>(
    r: &mut R,
) -> io::Result<Option<Frame<T>>> {
    let Some(body) = read_frame_bytes(r)? else {
        return Ok(None);
    };
    match serde_json::from_slice::<T>(&body) {
        Ok(v) => Ok(Some(Frame::Msg(v))),
        Err(e) => {
            // Only a well-formed JSON object is refusable. Anything else means
            // the peer is not speaking this protocol, and continuing to read
            // would be guessing.
            match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(serde_json::Value::Object(map)) => {
                    let tag = map
                        .get("op")
                        .or_else(|| map.get("t"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("(untagged)")
                        .to_string();
                    Ok(Some(Frame::Unknown { tag }))
                }
                _ => Err(invalid(e)),
            }
        }
    }
}

fn read_frame_bytes<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(invalid("frame exceeds cap"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

pub fn read_msg<R: Read, T: serde::de::DeserializeOwned>(r: &mut R) -> io::Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(invalid("frame exceeds cap"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map(Some).map_err(invalid)
}

/// Write one raw binary data frame (data plane for Cat).
/// Format: `u32 LE length || raw bytes` — same framing as JSON, but content is raw.
pub fn write_data_frame<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| invalid("data frame too large"))?;
    if len > MAX_FRAME {
        return Err(invalid("data frame exceeds cap"));
    }
    w.write_all(&len.to_le_bytes())?;
    w.write_all(data)?;
    w.flush()
}

/// Read one raw binary data frame (data plane for Cat).
/// Returns `Ok(None)` on a clean EOF.
pub fn read_data_frame<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(invalid("data frame exceeds cap"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

fn invalid<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pvfs_core::identity;

    #[test]
    fn frame_roundtrip() {
        let msg = ServerMsg::Ls {
            children: vec![ChildInfo {
                id: "ab".into(),
                label: "docs".into(),
                node_type: "folder".into(),
            }],
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &msg).unwrap();
        let mut cur = std::io::Cursor::new(buf);
        let got: ServerMsg = read_msg(&mut cur).unwrap().unwrap();
        assert_eq!(got, msg);
        // a second read hits clean EOF
        assert!(read_msg::<_, ServerMsg>(&mut cur).unwrap().is_none());
    }

    #[test]
    fn data_frame_roundtrip() {
        let data = b"hello pvfs data plane";
        let mut buf = Vec::new();
        write_data_frame(&mut buf, data).unwrap();
        let mut cur = std::io::Cursor::new(buf);
        let got = read_data_frame(&mut cur).unwrap().unwrap();
        assert_eq!(got, data);
        assert!(read_data_frame(&mut cur).unwrap().is_none());
    }

    #[test]
    fn auth_digest_binds_inputs_and_verifies() {
        let d1 = auth_digest(b"nonce-1", "forest-A", 100);
        assert_eq!(d1, auth_digest(b"nonce-1", "forest-A", 100), "deterministic");
        assert_ne!(d1, auth_digest(b"nonce-2", "forest-A", 100), "nonce bound");
        assert_ne!(d1, auth_digest(b"nonce-1", "forest-B", 100), "forest bound");

        // a real key signs the digest and the signature verifies
        let key = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
        let pubkey = crypto::pubkey_bytes(&key);
        let sig = crypto::sign_digest(&key, &d1).unwrap();
        assert!(crypto::verify_digest(&pubkey, &d1, &sig).is_ok());
        // a different digest must not verify
        let d2 = auth_digest(b"nonce-2", "forest-A", 100);
        assert!(crypto::verify_digest(&pubkey, &d2, &sig).is_err());
    }
}
