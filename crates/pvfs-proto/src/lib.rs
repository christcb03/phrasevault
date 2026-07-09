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
pub const PROTO_VERSION: u32 = 2;
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
    /// A typed failure; `code` mirrors a `PvfsError` family.
    Error { code: String, message: String },
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
    /// Re-home `node` under `new_parent`.
    Mv { node: String, new_parent: String },
    /// Set a principal's rights on a node. `principal` = `public`|`any`|`tag:<name>`|
    /// `key:<hex>`; `rights` = `rwa` letters or `-` to clear.
    SetAcl {
        node: String,
        principal: String,
        rights: String,
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
    /// frames (`write_data_frame`), then CatDone.
    Cat { node: String },
    /// Stream a **secure** blob's ciphertext (doc 12 §8), verified against the
    /// signed ledger first. Same wire shape as `Cat` (CatStart → frames → CatDone).
    SecureCat { node: String },
    /// Upload a secure blob's new ciphertext, then advance its ledger. The client
    /// sends this, then binary data frames terminated by a zero-length frame; the
    /// server writes the bytes and replies `Prepared` (the `SecureBlobUpdated`
    /// digest to sign), after which the client `Commit`s as usual.
    SecurePut { node: String },
    /// Phase 1 of a write: ask the daemon to build the signable events for `op`.
    PrepareWrite { op: WriteOp },
    /// Phase 2: return one signature (hex) per preimage, in order.
    Commit {
        prepared_id: String,
        sigs: Vec<String>,
    },
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
