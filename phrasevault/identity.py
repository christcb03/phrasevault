"""
phrasevault/identity.py
────────────────────────
secp256k1 identity — keypairs, signing, verification, Ethereum/DID compatibility.

Every user has exactly one identity keypair derived from their passphrase via
Argon2id.  The passphrase IS the master secret: same passphrase → same seed →
same keypair → same DID, always, on any device, with no stored secrets.

Cryptographic stack:
  Argon2id     — memory-hard key stretching before seed derivation (~1s, 64 MB)
  BLAKE3       — domain-separated deterministic salt
  secp256k1    — the same elliptic curve used by Bitcoin and Ethereum
  coincurve    — libsecp256k1 Python bindings (same C library as Bitcoin Core)
  keccak256    — Ethereum address derivation from public key
  did:ethr     — W3C Decentralized Identifier method (Ethereum-compatible)

Why the passphrase derives the identity:
  - No key files to back up or lose
  - Same identity across all devices with the same passphrase
  - Passphrase loss = identity loss (same as Bitcoin wallet)
  - Future Ethereum payment layer reuses the same key

Signature format: 65-byte recoverable ECDSA (Ethereum-compatible).
  - Anyone can recover the signer's public key from a signature + message
  - No need to send public key alongside every signed message
  - Direct compatibility with eth_sign, EIP-712, etc.

Public key storage: 33-byte compressed secp256k1 (stored in DB, never secret).
Private key: NEVER stored — always re-derived from passphrase when needed.
"""

import blake3 as _blake3
import coincurve
from Crypto.Hash import keccak as _keccak_module
from argon2.low_level import hash_secret_raw, Type

from . import crypto


# ─── Domain-separation tag (ensures identity derivation can't collide with
#     the address/key derivation paths in crypto.py) ─────────────────────────
TAG_IDENTITY = b"phrasevault:identity:v1:"


# ══════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _keccak256(data: bytes) -> bytes:
    """Standard Ethereum keccak256 hash."""
    k = _keccak_module.new(digest_bits=256)
    k.update(data)
    return k.digest()


# ══════════════════════════════════════════════════════════════════════════════
# 1. SEED DERIVATION
#    passphrase  →  32-byte secp256k1 private key seed
#    Argon2id ensures brute-forcing the passphrase from a captured seed is
#    as hard as brute-forcing the private key directly.
# ══════════════════════════════════════════════════════════════════════════════

def derive_identity_seed(passphrase: str) -> bytes:
    """
    Deterministically derive a 32-byte secp256k1 seed from a passphrase.

    Pipeline:
      salt = BLAKE3(TAG_IDENTITY | passphrase)   [fast, deterministic]
      seed = Argon2id(passphrase, salt)           [slow, ~1s, 64 MB]

    Same passphrase → same seed → same keypair → same Ethereum address → same DID.
    No state required; works identically on any device.
    """
    salt = _blake3.blake3(TAG_IDENTITY + passphrase.encode("utf-8")).digest()
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=crypto.ARGON2_TIME_COST,
        memory_cost=crypto.ARGON2_MEMORY_COST,
        parallelism=crypto.ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2. KEYPAIR
#    seed  →  (private_key_bytes, compressed_public_key_bytes)
# ══════════════════════════════════════════════════════════════════════════════

def keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """
    32-byte seed → (private_key_bytes, compressed_public_key_bytes).

    private_key_bytes : 32 bytes  — the raw secp256k1 scalar (NEVER store unencrypted)
    compressed_pubkey : 33 bytes  — 0x02/0x03 prefix + 32-byte x-coordinate (public)
    """
    privkey = coincurve.PrivateKey(secret=seed)
    return seed, privkey.public_key.format(compressed=True)


# ══════════════════════════════════════════════════════════════════════════════
# 3. ADDRESS AND DID DERIVATION
#    compressed_pubkey  →  Ethereum address  →  DID
# ══════════════════════════════════════════════════════════════════════════════

def pubkey_to_eth_address(compressed_pubkey: bytes) -> str:
    """
    secp256k1 compressed public key → Ethereum-style 0x... address.

    Standard Ethereum derivation:
      1. Decompress pubkey to 64-byte uncompressed form (strip 0x04 prefix)
      2. keccak256(uncompressed_pubkey)
      3. Take last 20 bytes → 40 hex chars → prepend '0x'
    """
    uncompressed = coincurve.PublicKey(compressed_pubkey).format(compressed=False)
    uncompressed_body = uncompressed[1:]              # strip 0x04 prefix → 64 bytes
    return "0x" + _keccak256(uncompressed_body)[-20:].hex()


def pubkey_to_did(compressed_pubkey: bytes) -> str:
    """
    secp256k1 compressed public key → did:ethr:0x... DID string.

    The did:ethr method maps an Ethereum address to a W3C DID.
    Future: can be anchored on-chain for on-chain resolution.
    """
    return f"did:ethr:{pubkey_to_eth_address(compressed_pubkey)}"


# ══════════════════════════════════════════════════════════════════════════════
# 4. SIGNING
#    private_key + message  →  65-byte recoverable signature
# ══════════════════════════════════════════════════════════════════════════════

def sign(private_key_bytes: bytes, message: bytes) -> bytes:
    """
    Sign a message with secp256k1.

    Returns a 65-byte recoverable ECDSA signature (Ethereum-compatible):
      bytes[0..63]  — (r, s) — the signature itself
      bytes[64]     — v      — recovery byte (0 or 1)

    The message is hashed with keccak256 before signing (standard Ethereum practice).
    The recovery byte means the signer's public key can be recovered from just
    the signature + original message — no need to send the pubkey separately.
    """
    privkey = coincurve.PrivateKey(secret=private_key_bytes)
    msg_hash = _keccak256(message)
    return privkey.sign_recoverable(msg_hash, hasher=None)


# ══════════════════════════════════════════════════════════════════════════════
# 5. VERIFICATION
#    compressed_pubkey + message + signature  →  bool
# ══════════════════════════════════════════════════════════════════════════════

def verify(compressed_pubkey: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify a recoverable secp256k1 signature.

    Recovers the public key from the signature and compares it to the expected
    public key.  Never raises — returns False on any failure (malformed inputs,
    wrong key, tampered signature, etc.).

    Why recovery-based verification instead of direct verify?
    The coincurve API for recoverable sigs works via recovery — this is also how
    Ethereum internally validates signatures (ecrecover).
    """
    try:
        msg_hash = _keccak256(message)
        recovered = coincurve.PublicKey.from_signature_and_message(
            signature, msg_hash, hasher=None
        )
        return recovered.format(compressed=True) == compressed_pubkey
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 6. PUBLIC KEY RECOVERY
#    message + signature  →  compressed_pubkey (or None)
# ══════════════════════════════════════════════════════════════════════════════

def recover_public_key(message: bytes, signature: bytes) -> bytes | None:
    """
    Recover the compressed public key from a recoverable signature.

    Useful when the verifier doesn't already know who signed — they can recover
    the key and then look up who owns it.  Returns None on failure.
    """
    try:
        msg_hash = _keccak256(message)
        pubkey = coincurve.PublicKey.from_signature_and_message(
            signature, msg_hash, hasher=None
        )
        return pubkey.format(compressed=True)
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# 7. CONVENIENCE: FULL IDENTITY INFO
# ══════════════════════════════════════════════════════════════════════════════

def identity_info(compressed_pubkey: bytes) -> dict:
    """
    Return a dict summarising a public key's identity:
      public_key_hex  — 66-char hex string (for sharing, storage, JWT sub field)
      eth_address     — '0x...' Ethereum address
      did             — 'did:ethr:0x...' W3C DID
    """
    return {
        "public_key_hex": compressed_pubkey.hex(),
        "eth_address":    pubkey_to_eth_address(compressed_pubkey),
        "did":            pubkey_to_did(compressed_pubkey),
    }
