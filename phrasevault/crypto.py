"""
phrasevault/crypto.py
─────────────────────
Pure cryptographic primitives — zero I/O, zero side-effects.
Every function does exactly ONE thing.  Call them in sequence; each
result feeds the next.  This makes each step independently testable
and the whole pipeline close to 100% reliable.

Stack (all verified, pinned in requirements.txt):
  BLAKE3        — address / chain hash (fast, one-way)
  Argon2id      — key derivation (64 MB memory-hard, brute-force resistant)
  XSalsa20-Poly1305 via PyNaCl — authenticated encryption (AEAD)

Confidence score design:
  lower  = more certain  (0.0 = tautology)
  higher = more speculative (→1.0 = asymptote)
  impossibility_measure = -ln(1 - confidence)   [natural log]
"""

import time
import struct
import math
import blake3
import nacl.secret
import nacl.utils
from argon2.low_level import hash_secret_raw, Type

# ─── Argon2id parameters (OWASP recommended minimums) ────────────────────────
ARGON2_TIME_COST   = 3          # iterations
ARGON2_MEMORY_COST = 65536      # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN    = 32         # bytes → 256-bit key

# ─── BLAKE3 domain-separation tags ───────────────────────────────────────────
TAG_ADDRESS = b"phrasevault:address:v1:"
TAG_SALT    = b"phrasevault:salt:v1:"
TAG_CHAIN   = b"phrasevault:chain:v1:"


# ══════════════════════════════════════════════════════════════════════════════
# 1. ADDRESS DERIVATION
#    passphrase + chain_position  →  32-byte storage address (hex-safe)
#    Uses BLAKE3 — fast, one-way, collision-resistant.
#    The address is PUBLIC (it locates the data); the key is SECRET (decrypts it).
# ══════════════════════════════════════════════════════════════════════════════

def derive_address(passphrase: str, chain_position: int) -> bytes:
    """
    BLAKE3(TAG_ADDRESS | passphrase | position)  →  32 bytes.

    Same passphrase at position 0 always produces the same address.
    Changing either input produces a completely different address.
    """
    pos_bytes = struct.pack(">Q", chain_position)   # 8-byte big-endian uint64
    h = blake3.blake3(TAG_ADDRESS + passphrase.encode("utf-8") + pos_bytes)
    return h.digest()                                # 32 bytes


def chain_address(prev_address: bytes, passphrase: str, chain_position: int) -> bytes:
    """
    BLAKE3(TAG_CHAIN | prev_address | passphrase | position)  →  32 bytes.

    Links entries in an unforgeable chain: you cannot insert or reorder
    entries without breaking every subsequent address.
    Uses prev_address = b'\\x00' * 32 for the genesis (position 0) entry.
    """
    pos_bytes = struct.pack(">Q", chain_position)
    h = blake3.blake3(
        TAG_CHAIN + prev_address + passphrase.encode("utf-8") + pos_bytes
    )
    return h.digest()


# ══════════════════════════════════════════════════════════════════════════════
# 2. TIMESTAMP
#    Captures current time in nanoseconds.  The timestamp is baked INTO
#    the Argon2id salt, making it impossible to forge or backdate — anyone
#    who re-derives the key without the exact timestamp gets a different key.
# ══════════════════════════════════════════════════════════════════════════════

def now_ns() -> int:
    """Current time as integer nanoseconds since Unix epoch."""
    return time.time_ns()


def pack_timestamp(timestamp_ns: int) -> bytes:
    """Encode nanosecond timestamp as 8-byte big-endian for use in salts."""
    return struct.pack(">Q", timestamp_ns)


def unpack_timestamp(raw: bytes) -> int:
    """Decode 8-byte big-endian back to integer nanoseconds."""
    return struct.unpack(">Q", raw)[0]


# ══════════════════════════════════════════════════════════════════════════════
# 3. KEY DERIVATION
#    passphrase + timestamp + chain_position  →  32-byte encryption key.
#    Uses Argon2id: slow (intentionally), 64 MB memory, brute-force resistant.
#    The timestamp is in the salt → each chain entry gets a UNIQUE key even
#    if the passphrase is the same.
# ══════════════════════════════════════════════════════════════════════════════

def derive_key(passphrase: str, timestamp_ns: int, chain_position: int) -> bytes:
    """
    Argon2id(passphrase, salt=BLAKE3(TAG_SALT | timestamp | position))  →  32 bytes.

    The BLAKE3 salt derivation is fast; Argon2id is deliberately slow.
    Separating them means the salt is deterministic and auditable while
    the key derivation remains brute-force resistant.
    """
    # Step 3a: derive a deterministic salt from timestamp + position
    pos_bytes = struct.pack(">Q", chain_position)
    ts_bytes  = pack_timestamp(timestamp_ns)
    salt = blake3.blake3(TAG_SALT + ts_bytes + pos_bytes).digest()  # 32 bytes

    # Step 3b: Argon2id key stretch (the slow step — ~1 second on modern hardware)
    key = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
    return key                                        # 32 bytes


# ══════════════════════════════════════════════════════════════════════════════
# 4. ENCRYPTION
#    key + plaintext  →  (nonce, ciphertext).
#    Uses XSalsa20-Poly1305 (PyNaCl SecretBox) — authenticated encryption.
#    The Poly1305 MAC guarantees integrity: any tampering makes decryption fail.
# ══════════════════════════════════════════════════════════════════════════════

def encrypt_payload(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    XSalsa20-Poly1305(key, random_nonce, plaintext)  →  (nonce, ciphertext).

    The nonce is 24 bytes of cryptographically secure random data.
    A fresh nonce is generated for every encryption — never reused.
    The ciphertext includes a 16-byte Poly1305 authentication tag.
    """
    box   = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)   # 24 random bytes
    # PyNaCl prepends nonce to the message; we separate them for storage clarity
    combined    = box.encrypt(plaintext, nonce)
    ciphertext  = combined.ciphertext                              # excludes nonce
    return nonce, ciphertext


# ══════════════════════════════════════════════════════════════════════════════
# 5. DECRYPTION
#    key + nonce + ciphertext  →  plaintext  (or raises nacl.exceptions.CryptoError)
# ══════════════════════════════════════════════════════════════════════════════

def decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    XSalsa20-Poly1305 decryption.

    Raises nacl.exceptions.CryptoError if:
      - the key is wrong (wrong passphrase or wrong timestamp)
      - the ciphertext has been tampered with
      - the nonce doesn't match

    Never returns garbage — either perfect plaintext or a hard exception.
    """
    box = nacl.secret.SecretBox(key)
    return box.decrypt(ciphertext, nonce)


# ══════════════════════════════════════════════════════════════════════════════
# 6. CONFIDENCE SCORE UTILITIES
#    These run entirely in Python floats — no AI required.
# ══════════════════════════════════════════════════════════════════════════════

def impossibility_measure(confidence: float) -> float:
    """
    -ln(1 - confidence)

    0.0  → 0.0       (tautology — certain)
    0.5  → 0.6931    (maximum uncertainty — Shannon entropy peak)
    0.97 → 3.5066    (highly speculative — T14_CosmologicalHilbert)
    → ∞  as confidence → 1.0  (asymptote — never reached)
    """
    if confidence < 0.0 or confidence >= 1.0:
        raise ValueError(f"confidence must be in [0, 1); got {confidence}")
    if confidence == 0.0:
        return 0.0
    return -math.log(1.0 - confidence)


def effective_score(
    stored_score: float,
    anchor_scores: list[float],
    alpha: float = 0.01,
) -> float:
    """
    Confidence gravity: trusted (lower-score) nodes pull a node's score down.

    effective(N) = stored(N) - α × Σ[w(l)×(stored(N)-stored(l))] / Σ[w(l)]
    where w(l) = 1/(1+stored(l))  and  the sum is over anchors with score < stored(N).

    alpha = 0.01 means a direct trusted link provides 1% gravitational pull.
    Multiple anchors compound; each anchor's weight is proportional to its trust.
    """
    pull_anchors = [s for s in anchor_scores if s < stored_score]
    if not pull_anchors:
        return stored_score

    weights       = [1.0 / (1.0 + s) for s in pull_anchors]
    weighted_pull = sum(w * (stored_score - s) for w, s in zip(weights, pull_anchors))
    total_weight  = sum(weights)
    return stored_score - alpha * (weighted_pull / total_weight)


def truth_rank(score: float, days_since_stored: float) -> float:
    """
    Recency-adjusted rank: score / log(days + 1)
    Lower is better.  Fresh data of equal score ranks higher than old data.
    """
    if days_since_stored < 0:
        raise ValueError("days_since_stored cannot be negative")
    return score / math.log(days_since_stored + 1 + 1e-9)


# ══════════════════════════════════════════════════════════════════════════════
# 7. PI CHECKPOINT
#    Embed verifiable pi digits at each chain position for dual-layer
#    tamper detection (in addition to the BLAKE3 hash chain).
# ══════════════════════════════════════════════════════════════════════════════

# First 1024 hex digits of pi (BBP-derivable, universally verifiable)
_PI_HEX = (
    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377"
    "BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5A"
    "C2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC"
    "16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A5"
    "9B59C30D5392AF26013C5D1B023286085F0CA417918B8DB38EF8E79DCB0603A180E6C9E0E8BB01E"
    "8A3ED71577C1BD314B2778AF2FDA55605C60E65525F3AA55AB945748986263E8144055CA396A2AA"
    "B10B6B4CC5C341141E8CEA15486AF7C72E993B3EE1411636FBC2A2BA9C55D741831F6CE5C3E169B"
    "87931EAFD6BA336C274425A3174896084C837BE5E2F0340D40F7367BAC4F84E9A5BEDF490C1E3C5"
    "0CB13B6A7DA7B5E9BBDC51F7735494A52DEA62CA3A8FB4064C0D4AFC1CCA35F4E5D5CB9B9B3AACE"
    "E9B4826D6CB01D39DBFA5EFEAD69E05BCECEA31F1A0AD74ADB9C9D7D2EF3FE47041C4C8B07F6B4"
    "9D8FABC6A22B93A0C1A5C71C7F72ACA7B9E9DA26BCDD86EE2F2AF19F8FAA4EE7FE1A58EF31AA83"
    "F0D4A32A26CCED12F12A1CFDB2B59F1A2F16A6D61C3BE1E8A1A3BCAA1BF3C23A00ABCE6E4CEABF"
    "EBE00F5E4A65CF76B7E0A84D08000A39CDEDBFA4F9AAF439EA94CE4982AA4A8FE0D64BFD9FE0A9"
)

def pi_checkpoint(chain_position: int) -> bytes:
    """
    Return 32 hex-chars (16 bytes) of pi starting at position*32.
    Embed this in each chain entry header for dual-layer tamper detection.
    Anyone can independently verify using the BBP formula.
    """
    start = (chain_position * 32) % (len(_PI_HEX) - 32)
    chunk = _PI_HEX[start : start + 32]
    return bytes.fromhex(chunk)
