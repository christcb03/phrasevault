//! Signing/verification helpers — spec §4.4.
//!
//! secp256k1 ECDSA over a 32-byte BLAKE3 digest (pre-hashed message, RFC 6979
//! deterministic nonces). Compact 64-byte r||s signatures. Low-s is enforced
//! on every verify path (anti-malleability, federation doc §3.5).

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;

use crate::error::{IntegrityReason, PvfsError, Result};

/// Compressed SEC1 public key bytes (33 bytes) for a signing key.
pub fn pubkey_bytes(key: &SigningKey) -> Vec<u8> {
    let pk = k256::PublicKey::from(key.verifying_key());
    pk.to_encoded_point(true).as_bytes().to_vec()
}

/// Sign a 32-byte digest; returns compact 64-byte low-s signature.
pub fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> Result<Vec<u8>> {
    let sig: Signature = key.sign_prehash(digest).map_err(|e| PvfsError::Identity {
        detail: format!("signing failed: {e}"),
    })?;
    // RFC 6979 in k256 already yields low-s; normalize defensively anyway.
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(sig.to_bytes().to_vec())
}

/// Verify a compact signature over a 32-byte digest against a compressed
/// public key. Rejects high-s (malleable) signatures.
pub fn verify_digest(author: &[u8], digest: &[u8; 32], sig: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_sec1_bytes(author).map_err(|_| PvfsError::Integrity {
        kind: "signature",
        id: hex::encode(author),
        reason: IntegrityReason::UnknownAuthor,
    })?;
    let sig = Signature::from_slice(sig).map_err(|_| PvfsError::Integrity {
        kind: "signature",
        id: hex::encode(author),
        reason: IntegrityReason::SignatureInvalid,
    })?;
    if sig.normalize_s().is_some() {
        // s was high — malleable form is rejected outright.
        return Err(PvfsError::Integrity {
            kind: "signature",
            id: hex::encode(author),
            reason: IntegrityReason::SignatureInvalid,
        });
    }
    vk.verify_prehash(digest, &sig)
        .map_err(|_| PvfsError::Integrity {
            kind: "signature",
            id: hex::encode(author),
            reason: IntegrityReason::SignatureInvalid,
        })
}

/// BLAKE3 of a domain prefix concatenated with a PCE body (spec §6 table).
pub fn domain_digest(prefix: &str, pce_body: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(prefix.as_bytes());
    h.update(pce_body);
    *h.finalize().as_bytes()
}
