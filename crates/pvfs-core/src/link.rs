//! Link — spec §5. Logical edge id `(parent_id, child_id, link_type,
//! link_nonce)`; `created_at` / `author` / `order_key` / state band are NOT
//! part of the id.

use crate::crypto;
use crate::encoding::Enc;
use crate::error::{IntegrityReason, PvfsError, Result};

pub type LinkId = String;

pub const LINK_CONTAINS: &str = "contains";
pub const LINK_REF: &str = "ref";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub id: LinkId,
    pub parent_id: Option<String>, // None ⇒ child is a tree root
    pub child_id: String,
    pub link_type: String,
    pub link_nonce: u64,
    pub order_key: String,
    pub created_at: u64,
    pub author: Vec<u8>,
    pub sig: Vec<u8>,
    // mutable state band (projection only)
    pub removed_at: Option<u64>,
    pub superseded_by: Option<String>,
    pub suspended_at: Option<u64>,
}

pub fn preimage(
    parent_id: Option<&str>,
    child_id: &str,
    link_type: &str,
    link_nonce: u64,
) -> Vec<u8> {
    let mut e = Enc::new();
    e.opt_string(parent_id)
        .string(child_id)
        .string(link_type)
        .u64(link_nonce);
    e.finish()
}

pub fn compute_id_digest(
    parent_id: Option<&str>,
    child_id: &str,
    link_type: &str,
    link_nonce: u64,
) -> [u8; 32] {
    *blake3::hash(&preimage(parent_id, child_id, link_type, link_nonce)).as_bytes()
}

impl Link {
    pub fn id_digest(&self) -> [u8; 32] {
        compute_id_digest(
            self.parent_id.as_deref(),
            &self.child_id,
            &self.link_type,
            self.link_nonce,
        )
    }

    pub fn verify(&self) -> Result<()> {
        let digest = self.id_digest();
        let recomputed = hex::encode(digest);
        if recomputed != self.id {
            return Err(PvfsError::Integrity {
                kind: "link",
                id: self.id.clone(),
                reason: IntegrityReason::IdMismatch {
                    expected: self.id.clone(),
                    actual: recomputed,
                },
            });
        }
        crypto::verify_digest(&self.author, &digest, &self.sig).map_err(|_| {
            PvfsError::Integrity {
                kind: "link",
                id: self.id.clone(),
                reason: IntegrityReason::SignatureInvalid,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_id_excludes_mutable_and_audit_fields() {
        let a = compute_id_digest(Some("p"), "c", "contains", 0);
        // same logical edge ⇒ same id, regardless of who/when/order
        assert_eq!(a, compute_id_digest(Some("p"), "c", "contains", 0));
        // each preimage field changes the id
        assert_ne!(a, compute_id_digest(Some("q"), "c", "contains", 0));
        assert_ne!(a, compute_id_digest(Some("p"), "d", "contains", 0));
        assert_ne!(a, compute_id_digest(Some("p"), "c", "ref", 0));
        assert_ne!(a, compute_id_digest(Some("p"), "c", "contains", 1));
        assert_ne!(a, compute_id_digest(None, "c", "contains", 0));
    }
}
