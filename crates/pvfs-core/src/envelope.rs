//! The reference envelope (doc 12 §8.5): envelope encryption for secure blobs.
//!
//! - The **content key** is 32 random bytes; the payload is
//!   XChaCha20-Poly1305(content key) — the codebase's one AEAD.
//! - The content key is **wrapped per recipient** via ECIES-style ECDH on
//!   secp256k1: an ephemeral key per wrap, `blake3::derive_key` as the KDF,
//!   the same AEAD as the KEK cipher. Any one credential unwraps (§3).
//! - The serialized envelope (PCE, versioned) is what a secure blob's location
//!   stores and what the signed ledger hashes — ciphertext hash domain (§8.4).
//!
//! PVFS never persists the content key; the companion custodies the owner's
//! **encryption key** (`m/43'/20566'/2'/<id>'`) and returns *content keys* via
//! `secure_unwrap`, never private keys. Apps with their own key hierarchy skip
//! this module entirely and store their bytes with `--raw` (§5).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use k256::ecdsa::SigningKey;
use rand::RngCore;

use crate::encoding::{Dec, Enc};
use crate::error::{PvfsError, Result};

const VERSION: u64 = 1;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
/// KDF context strings (blake3 derive_key domain separation).
const KEK_CONTEXT: &str = "pvfs envelope v1 kek";

fn bad(reason: impl Into<String>) -> PvfsError {
    PvfsError::BadInput {
        field: "envelope".into(),
        reason: reason.into(),
    }
}

/// One recipient's wrapped copy of the content key.
#[derive(Clone)]
pub struct Wrap {
    /// Compressed SEC1 public key this wrap is addressed to (33 bytes).
    pub recipient_pubkey: Vec<u8>,
    /// The wrap's ephemeral public key (33 bytes).
    pub ephemeral_pubkey: Vec<u8>,
    /// AEAD nonce for the wrapped key.
    pub nonce: Vec<u8>,
    /// AEAD(kek, content key) — 48 bytes (32 + tag).
    pub wrapped_key: Vec<u8>,
}

/// A parsed envelope: the wraps plus the sealed payload.
pub struct Envelope {
    pub wraps: Vec<Wrap>,
    pub payload_nonce: Vec<u8>,
    pub payload: Vec<u8>,
}

/// ECDH(secret, peer) → KEK via blake3 derive_key.
fn kek(secret: &SigningKey, peer_pub: &[u8]) -> Result<[u8; KEY_LEN]> {
    let peer = k256::PublicKey::from_sec1_bytes(peer_pub)
        .map_err(|_| bad("bad public key in wrap"))?;
    let shared = k256::ecdh::diffie_hellman(secret.as_nonzero_scalar(), peer.as_affine());
    Ok(blake3::derive_key(KEK_CONTEXT, shared.raw_secret_bytes().as_slice()))
}

fn aead(key: &[u8; KEY_LEN]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| bad("bad key length"))
}

fn wrap_for(recipient_pub: &[u8], content_key: &[u8; KEY_LEN]) -> Result<Wrap> {
    crate::crypto::validate_pubkey(recipient_pub)?;
    // Fresh ephemeral key per wrap: the recipient recovers the KEK from
    // ECDH(recipient_secret, ephemeral_pub).
    let eph = SigningKey::random(&mut rand::thread_rng());
    let k = kek(&eph, recipient_pub)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let wrapped_key = aead(&k)?
        .encrypt(XNonce::from_slice(&nonce), content_key.as_slice())
        .map_err(|_| bad("wrap failed"))?;
    Ok(Wrap {
        recipient_pubkey: recipient_pub.to_vec(),
        ephemeral_pubkey: crate::crypto::pubkey_bytes(&eph),
        nonce: nonce.to_vec(),
        wrapped_key,
    })
}

/// Seal `plaintext` for `recipients` (compressed pubkeys): fresh content key,
/// one wrap each. Returns the serialized envelope — the bytes a secure blob
/// stores and the ledger hashes.
pub fn seal(plaintext: &[u8], recipients: &[Vec<u8>]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(bad("at least one recipient required"));
    }
    let mut content_key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut content_key);
    let mut payload_nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut payload_nonce);
    let payload = aead(&content_key)?
        .encrypt(XNonce::from_slice(&payload_nonce), plaintext)
        .map_err(|_| bad("seal failed"))?;
    let mut wraps = Vec::with_capacity(recipients.len());
    for r in recipients {
        wraps.push(wrap_for(r, &content_key)?);
    }
    Ok(encode(&Envelope {
        wraps,
        payload_nonce: payload_nonce.to_vec(),
        payload,
    }))
}

/// Parse envelope bytes (fails cleanly on anything that isn't a v1 envelope —
/// e.g. `--raw` app bytes).
pub fn parse(bytes: &[u8]) -> Result<Envelope> {
    let mut d = Dec::new(bytes, "envelope");
    let version = d.u64()?;
    if version != VERSION {
        return Err(bad(format!("unsupported envelope version {version}")));
    }
    let n = d.u64()? as usize;
    if n == 0 || n > 4096 {
        return Err(bad("implausible wrap count"));
    }
    let mut wraps = Vec::with_capacity(n);
    for _ in 0..n {
        wraps.push(Wrap {
            recipient_pubkey: d.bytes()?,
            ephemeral_pubkey: d.bytes()?,
            nonce: d.bytes()?,
            wrapped_key: d.bytes()?,
        });
    }
    let payload_nonce = d.bytes()?;
    let payload = d.bytes()?;
    d.finish()?;
    Ok(Envelope {
        wraps,
        payload_nonce,
        payload,
    })
}

fn encode(env: &Envelope) -> Vec<u8> {
    let mut e = Enc::new();
    e.u64(VERSION).u64(env.wraps.len() as u64);
    for w in &env.wraps {
        e.bytes(&w.recipient_pubkey)
            .bytes(&w.ephemeral_pubkey)
            .bytes(&w.nonce)
            .bytes(&w.wrapped_key);
    }
    e.bytes(&env.payload_nonce).bytes(&env.payload);
    e.finish()
}

impl Envelope {
    /// The wrap addressed to `recipient_pub`, if any.
    pub fn wrap_for(&self, recipient_pub: &[u8]) -> Option<&Wrap> {
        self.wraps.iter().find(|w| w.recipient_pubkey == recipient_pub)
    }
}

/// Recover the content key from a wrap with the recipient's **secret** key —
/// this is what the companion runs behind `secure_unwrap` (doc 12 §8.5). The
/// content key comes back; the secret never leaves the caller.
pub fn unwrap_content_key(wrap: &Wrap, recipient_secret: &SigningKey) -> Result<[u8; KEY_LEN]> {
    let k = kek(recipient_secret, &wrap.ephemeral_pubkey)?;
    if wrap.nonce.len() != NONCE_LEN {
        return Err(bad("bad wrap nonce"));
    }
    let key = aead(&k)?
        .decrypt(XNonce::from_slice(&wrap.nonce), wrap.wrapped_key.as_slice())
        .map_err(|_| bad("unwrap failed: wrong key or tampered wrap"))?;
    key.try_into().map_err(|_| bad("unwrapped key has wrong length"))
}

/// Decrypt the payload with an already-unwrapped content key.
pub fn open_with_key(env: &Envelope, content_key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    if env.payload_nonce.len() != NONCE_LEN {
        return Err(bad("bad payload nonce"));
    }
    aead(content_key)?
        .decrypt(
            XNonce::from_slice(&env.payload_nonce),
            env.payload.as_slice(),
        )
        .map_err(|_| bad("decrypt failed: wrong content key or tampered payload"))
}

/// Re-serialize with an extra recipient (doc 12 §8.6 `secure grant`): the
/// payload is untouched; only a new wrap is added. Requires the content key —
/// only an existing key-holder can grant.
pub fn add_recipient(
    bytes: &[u8],
    content_key: &[u8; KEY_LEN],
    new_recipient_pub: &[u8],
) -> Result<Vec<u8>> {
    let mut env = parse(bytes)?;
    if env.wrap_for(new_recipient_pub).is_some() {
        return Ok(bytes.to_vec()); // already a recipient — idempotent
    }
    // Prove the caller actually holds the content key before growing the ACL.
    open_with_key(&env, content_key)?;
    env.wraps.push(wrap_for(new_recipient_pub, content_key)?);
    Ok(encode(&env))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::identity;

    fn keypair() -> (SigningKey, Vec<u8>) {
        let k = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
        let pk = crypto::pubkey_bytes(&k);
        (k, pk)
    }

    #[test]
    fn seal_unwrap_open_round_trip_multi_recipient() {
        let (alice, alice_pub) = keypair();
        let (bob, bob_pub) = keypair();
        let sealed = seal(b"the plaintext", &[alice_pub.clone(), bob_pub.clone()]).unwrap();

        // Either recipient unwraps and reads.
        for (key, pubkey) in [(&alice, &alice_pub), (&bob, &bob_pub)] {
            let env = parse(&sealed).unwrap();
            let wrap = env.wrap_for(pubkey).expect("wrap present");
            let ck = unwrap_content_key(wrap, key).unwrap();
            assert_eq!(open_with_key(&env, &ck).unwrap(), b"the plaintext");
        }
    }

    #[test]
    fn strangers_and_tampering_fail() {
        let (_alice, alice_pub) = keypair();
        let (mallory, mallory_pub) = keypair();
        let sealed = seal(b"secret", &[alice_pub.clone()]).unwrap();
        let env = parse(&sealed).unwrap();

        // No wrap for a stranger; using Alice's wrap with the wrong key fails.
        assert!(env.wrap_for(&mallory_pub).is_none());
        let wrap = env.wrap_for(&alice_pub).unwrap();
        assert!(unwrap_content_key(wrap, &mallory).is_err());

        // A flipped payload byte fails the AEAD even with the right key.
        let (alice, alice_pub) = keypair();
        let sealed = seal(b"secret", &[alice_pub.clone()]).unwrap();
        let mut env = parse(&sealed).unwrap();
        let ck = unwrap_content_key(env.wrap_for(&alice_pub).unwrap(), &alice).unwrap();
        env.payload[0] ^= 1;
        assert!(open_with_key(&env, &ck).is_err());
    }

    #[test]
    fn grant_adds_a_recipient_without_reencrypting() {
        let (alice, alice_pub) = keypair();
        let (bob, bob_pub) = keypair();
        let sealed = seal(b"shared later", &[alice_pub.clone()]).unwrap();

        let env = parse(&sealed).unwrap();
        let ck = unwrap_content_key(env.wrap_for(&alice_pub).unwrap(), &alice).unwrap();
        let granted = add_recipient(&sealed, &ck, &bob_pub).unwrap();

        // Bob can now read; the payload bytes were not re-encrypted.
        let env2 = parse(&granted).unwrap();
        let ck_bob = unwrap_content_key(env2.wrap_for(&bob_pub).unwrap(), &bob).unwrap();
        assert_eq!(open_with_key(&env2, &ck_bob).unwrap(), b"shared later");
        assert_eq!(env2.payload, env.payload);
        // Idempotent: granting again changes nothing.
        assert_eq!(add_recipient(&granted, &ck, &bob_pub).unwrap(), granted);

        // A wrong content key cannot grant.
        assert!(add_recipient(&sealed, &[9u8; 32], &bob_pub).is_err());
    }

    #[test]
    fn raw_bytes_are_not_an_envelope() {
        assert!(parse(b"app-managed ciphertext").is_err());
        assert!(parse(b"").is_err());
    }
}
