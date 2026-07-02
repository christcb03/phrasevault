//! Node — spec §4. Immutable, content-addressed, signed.

use crate::crypto;
use crate::encoding::{Dec, Enc};
use crate::error::{IntegrityReason, PvfsError, Result};

pub type NodeId = String; // 64 hex chars (BLAKE3-256)

pub const TYPE_FILE: &str = "file";
pub const TYPE_FOLDER: &str = "folder";
/// A secure blob (doc 12): stable node identity, opaque mutable ciphertext at
/// its location, content described only by the `secure_blobs` ledger projection.
pub const TYPE_SECURE: &str = "secure";
pub const VISIBILITY_PUBLIC: &str = "public";
pub const LABEL_SOFT_CAP: usize = 4096; // spec §3

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: NodeId,
    pub node_type: String,
    pub label: String,
    pub visibility: String,
    pub payload: Vec<u8>,
    pub is_temp: bool,
    pub creation_nonce: u64,
    pub created_at: u64,
    pub author: Vec<u8>, // 33-byte compressed secp256k1 pubkey
    pub sig: Vec<u8>,    // 64-byte compact signature over id digest
}

/// Canonical preimage — spec §4.2 field order.
#[allow(clippy::too_many_arguments)]
pub fn preimage(
    node_type: &str,
    label: &str,
    visibility: &str,
    payload: &[u8],
    is_temp: bool,
    creation_nonce: u64,
    created_at: u64,
    author: &[u8],
) -> Vec<u8> {
    let mut e = Enc::new();
    e.string(node_type)
        .string(label)
        .string(visibility)
        .bytes(payload)
        .boolean(is_temp)
        .u64(creation_nonce)
        .u64(created_at)
        .bytes(author);
    e.finish()
}

#[allow(clippy::too_many_arguments)]
pub fn compute_id_digest(
    node_type: &str,
    label: &str,
    visibility: &str,
    payload: &[u8],
    is_temp: bool,
    creation_nonce: u64,
    created_at: u64,
    author: &[u8],
) -> [u8; 32] {
    *blake3::hash(&preimage(
        node_type,
        label,
        visibility,
        payload,
        is_temp,
        creation_nonce,
        created_at,
        author,
    ))
    .as_bytes()
}

impl Node {
    pub fn id_digest(&self) -> [u8; 32] {
        compute_id_digest(
            &self.node_type,
            &self.label,
            &self.visibility,
            &self.payload,
            self.is_temp,
            self.creation_nonce,
            self.created_at,
            &self.author,
        )
    }

    /// Recompute id and verify the signature — spec §4.4.
    pub fn verify(&self) -> Result<()> {
        let digest = self.id_digest();
        let recomputed = hex::encode(digest);
        if recomputed != self.id {
            return Err(PvfsError::Integrity {
                kind: "node",
                id: self.id.clone(),
                reason: IntegrityReason::IdMismatch {
                    expected: self.id.clone(),
                    actual: recomputed,
                },
            });
        }
        crypto::verify_digest(&self.author, &digest, &self.sig).map_err(|_| {
            PvfsError::Integrity {
                kind: "node",
                id: self.id.clone(),
                reason: IntegrityReason::SignatureInvalid,
            }
        })
    }
}

/// `file` payload — spec §4.3. Locations are events, never part of this.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilePayload {
    pub content_hash: String, // BLAKE3 hex of the bytes, "" if not yet hashed
    pub size_bytes: u64,
    pub mime_type: String,
    pub original_name: String,
}

impl FilePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.string(&self.content_hash)
            .u64(self.size_bytes)
            .string(&self.mime_type)
            .string(&self.original_name);
        e.finish()
    }

    pub fn decode(data: &[u8]) -> Result<FilePayload> {
        let mut d = Dec::new(data, "file payload");
        let p = FilePayload {
            content_hash: d.string()?,
            size_bytes: d.u64()?,
            mime_type: d.string()?,
            original_name: d.string()?,
        };
        d.finish()?;
        Ok(p)
    }
}

/// `folder` payload is the empty byte string in P0 (spec §4.3).
pub fn folder_payload() -> Vec<u8> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_changes_with_any_preimage_field() {
        let base = compute_id_digest("file", "a", "public", b"p", false, 1, 2, b"k");
        assert_ne!(
            base,
            compute_id_digest("folder", "a", "public", b"p", false, 1, 2, b"k")
        );
        assert_ne!(
            base,
            compute_id_digest("file", "b", "public", b"p", false, 1, 2, b"k")
        );
        assert_ne!(
            base,
            compute_id_digest("file", "a", "public", b"q", false, 1, 2, b"k")
        );
        assert_ne!(
            base,
            compute_id_digest("file", "a", "public", b"p", true, 1, 2, b"k")
        );
        assert_ne!(
            base,
            compute_id_digest("file", "a", "public", b"p", false, 9, 2, b"k")
        );
        assert_ne!(
            base,
            compute_id_digest("file", "a", "public", b"p", false, 1, 9, b"k")
        );
        assert_ne!(
            base,
            compute_id_digest("file", "a", "public", b"p", false, 1, 2, b"K")
        );
        // and is stable for identical input
        assert_eq!(
            base,
            compute_id_digest("file", "a", "public", b"p", false, 1, 2, b"k")
        );
    }

    #[test]
    fn file_payload_roundtrip() {
        let p = FilePayload {
            content_hash: "ab".into(),
            size_bytes: 42,
            mime_type: "video/mkv".into(),
            original_name: "x.mkv".into(),
        };
        assert_eq!(FilePayload::decode(&p.encode()).unwrap(), p);
    }
}
