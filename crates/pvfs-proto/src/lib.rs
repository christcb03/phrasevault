//! PVFS daemon/client wire protocol (doc 07).
//!
//! - Transport: length-prefixed JSON frames (`u32` LE length || JSON body).
//! - Auth: challenge-response — the daemon sends a nonce, the client signs
//!   [`auth_digest`] with its identity key; the proven key is the principal.
//! - Messages: [`ServerMsg`] / [`ClientMsg`]. The write path (PrepareWrite/Commit)
//!   and `Cat` land in later slices; v1 here is the handshake + read ops.

use std::io::{self, Read, Write};

use pvfs_core::crypto;
use pvfs_core::encoding::Enc;
use serde::{Deserialize, Serialize};

/// Bumped when the wire format changes incompatibly.
pub const PROTO_VERSION: u32 = 1;
/// Hard cap on a single control frame (bulk bytes use the data plane, not frames).
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

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
    /// Phase 1 of a write: the digests to sign (hex), plus the id the write yields.
    Prepared {
        prepared_id: String,
        preimages: Vec<String>,
        result_id: String,
    },
    /// Phase 2 result: the committed write's id.
    Committed { id: String },
    /// A chunk of file bytes (hex); `eof` once the file is exhausted.
    CatData { data: String, eof: bool },
    /// A typed failure; `code` mirrors a `PvfsError` family.
    Error { code: String, message: String },
}

/// A high-level write intent the daemon turns into signable events (doc 07 §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WriteOp {
    /// Create a folder named `label` under `parent`.
    Mkdir { parent: String, label: String },
    /// Create a file node named `label` under `parent` (metadata only; bytes are
    /// recorded separately by a location).
    AddFile {
        parent: String,
        label: String,
        size: u64,
        mime: String,
    },
    /// Unlink `node` from its home parent (soft remove).
    Rm { node: String },
    /// Record where a file node's bytes live.
    AddLocation { file: String, uri: String },
    /// Re-home `node` under `new_parent`.
    Mv { node: String, new_parent: String },
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
    /// Read up to `len` bytes of a file node starting at `offset`.
    Cat { node: String, offset: u64, len: u64 },
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
}

/// The 32-byte digest a client signs to prove key possession (doc 07 §2). Binds
/// the nonce, the forest id, and an expiry so a signature for one forest/window
/// can't be replayed to another.
pub fn auth_digest(nonce: &[u8], forest_id: &str, expiry_ms: u64) -> [u8; 32] {
    let mut e = Enc::new();
    e.bytes(nonce).string(forest_id).u64(expiry_ms);
    crypto::domain_digest("pvfs:daemon-auth:v1:", &e.finish())
}

/// Write one length-prefixed JSON frame.
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

/// Read one length-prefixed JSON frame; `Ok(None)` on a clean EOF.
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
