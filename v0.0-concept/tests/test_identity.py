"""
tests/test_identity.py
──────────────────────
Tests for the secp256k1 identity layer (phrasevault/identity.py).

Covers:
  - Deterministic seed derivation
  - Keypair generation
  - Ethereum address + DID format
  - Sign / verify roundtrip
  - Wrong-key rejection
  - Public key recovery
  - Vault-level create_identity / get_identity / sign_message / verify_signature
"""

import pytest
from phrasevault import identity as id_mod
from phrasevault.vault import Vault


# ─── test fixtures ────────────────────────────────────────────────────────────

PASS_A = "correct horse battery staple"
PASS_B = "different passphrase entirely"
MESSAGE = b"Hello, PhraseVault network"


# ══════════════════════════════════════════════════════════════════════════════
# 1. SEED DERIVATION
# ══════════════════════════════════════════════════════════════════════════════

def test_derive_identity_seed_is_32_bytes():
    seed = id_mod.derive_identity_seed(PASS_A)
    assert isinstance(seed, bytes)
    assert len(seed) == 32


def test_derive_identity_seed_deterministic():
    """Same passphrase must always produce the same seed."""
    seed1 = id_mod.derive_identity_seed(PASS_A)
    seed2 = id_mod.derive_identity_seed(PASS_A)
    assert seed1 == seed2


def test_derive_identity_seed_different_passphrases():
    """Different passphrases must produce completely different seeds."""
    seed_a = id_mod.derive_identity_seed(PASS_A)
    seed_b = id_mod.derive_identity_seed(PASS_B)
    assert seed_a != seed_b


# ══════════════════════════════════════════════════════════════════════════════
# 2. KEYPAIR
# ══════════════════════════════════════════════════════════════════════════════

def test_keypair_from_seed_shapes():
    seed = id_mod.derive_identity_seed(PASS_A)
    privkey, pubkey = id_mod.keypair_from_seed(seed)
    assert len(privkey) == 32
    assert len(pubkey) == 33         # compressed secp256k1


def test_keypair_is_deterministic():
    seed = id_mod.derive_identity_seed(PASS_A)
    _, pub1 = id_mod.keypair_from_seed(seed)
    _, pub2 = id_mod.keypair_from_seed(seed)
    assert pub1 == pub2


def test_compressed_pubkey_prefix():
    """Compressed secp256k1 keys start with 0x02 or 0x03."""
    seed = id_mod.derive_identity_seed(PASS_A)
    _, pubkey = id_mod.keypair_from_seed(seed)
    assert pubkey[0] in (0x02, 0x03)


# ══════════════════════════════════════════════════════════════════════════════
# 3. ETHEREUM ADDRESS + DID
# ══════════════════════════════════════════════════════════════════════════════

def test_eth_address_format():
    seed = id_mod.derive_identity_seed(PASS_A)
    _, pubkey = id_mod.keypair_from_seed(seed)
    addr = id_mod.pubkey_to_eth_address(pubkey)
    assert addr.startswith("0x")
    assert len(addr) == 42           # '0x' + 40 hex chars


def test_eth_address_deterministic():
    seed = id_mod.derive_identity_seed(PASS_A)
    _, pubkey = id_mod.keypair_from_seed(seed)
    assert id_mod.pubkey_to_eth_address(pubkey) == id_mod.pubkey_to_eth_address(pubkey)


def test_did_format():
    seed = id_mod.derive_identity_seed(PASS_A)
    _, pubkey = id_mod.keypair_from_seed(seed)
    did = id_mod.pubkey_to_did(pubkey)
    assert did.startswith("did:ethr:0x")
    assert len(did) == len("did:ethr:") + 42


def test_different_passphrases_different_addresses():
    seed_a = id_mod.derive_identity_seed(PASS_A)
    seed_b = id_mod.derive_identity_seed(PASS_B)
    _, pub_a = id_mod.keypair_from_seed(seed_a)
    _, pub_b = id_mod.keypair_from_seed(seed_b)
    assert id_mod.pubkey_to_eth_address(pub_a) != id_mod.pubkey_to_eth_address(pub_b)


# ══════════════════════════════════════════════════════════════════════════════
# 4. SIGN / VERIFY
# ══════════════════════════════════════════════════════════════════════════════

def test_sign_returns_65_bytes():
    seed = id_mod.derive_identity_seed(PASS_A)
    privkey, _ = id_mod.keypair_from_seed(seed)
    sig = id_mod.sign(privkey, MESSAGE)
    assert isinstance(sig, bytes)
    assert len(sig) == 65           # recoverable ECDSA: 64 bytes + 1 recovery byte


def test_sign_verify_roundtrip():
    seed = id_mod.derive_identity_seed(PASS_A)
    privkey, pubkey = id_mod.keypair_from_seed(seed)
    sig = id_mod.sign(privkey, MESSAGE)
    assert id_mod.verify(pubkey, MESSAGE, sig) is True


def test_verify_wrong_key_fails():
    """Signature from key A must not verify against key B."""
    seed_a = id_mod.derive_identity_seed(PASS_A)
    seed_b = id_mod.derive_identity_seed(PASS_B)
    priv_a, _     = id_mod.keypair_from_seed(seed_a)
    _,      pub_b = id_mod.keypair_from_seed(seed_b)
    sig = id_mod.sign(priv_a, MESSAGE)
    assert id_mod.verify(pub_b, MESSAGE, sig) is False


def test_verify_tampered_message_fails():
    seed = id_mod.derive_identity_seed(PASS_A)
    privkey, pubkey = id_mod.keypair_from_seed(seed)
    sig = id_mod.sign(privkey, MESSAGE)
    assert id_mod.verify(pubkey, b"tampered message", sig) is False


def test_verify_tampered_signature_fails():
    seed = id_mod.derive_identity_seed(PASS_A)
    privkey, pubkey = id_mod.keypair_from_seed(seed)
    sig = id_mod.sign(privkey, MESSAGE)
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]   # flip first byte
    assert id_mod.verify(pubkey, MESSAGE, bad_sig) is False


def test_verify_empty_signature_does_not_raise():
    seed = id_mod.derive_identity_seed(PASS_A)
    _, pubkey = id_mod.keypair_from_seed(seed)
    assert id_mod.verify(pubkey, MESSAGE, b"") is False


# ══════════════════════════════════════════════════════════════════════════════
# 5. PUBLIC KEY RECOVERY
# ══════════════════════════════════════════════════════════════════════════════

def test_recover_public_key_matches():
    seed = id_mod.derive_identity_seed(PASS_A)
    privkey, pubkey = id_mod.keypair_from_seed(seed)
    sig = id_mod.sign(privkey, MESSAGE)
    recovered = id_mod.recover_public_key(MESSAGE, sig)
    assert recovered == pubkey


def test_recover_public_key_bad_sig_returns_none():
    assert id_mod.recover_public_key(MESSAGE, b"not a signature") is None


# ══════════════════════════════════════════════════════════════════════════════
# 6. IDENTITY INFO DICT
# ══════════════════════════════════════════════════════════════════════════════

def test_identity_info_keys():
    seed = id_mod.derive_identity_seed(PASS_A)
    _, pubkey = id_mod.keypair_from_seed(seed)
    info = id_mod.identity_info(pubkey)
    assert set(info.keys()) == {"public_key_hex", "eth_address", "did"}
    assert info["public_key_hex"] == pubkey.hex()
    assert info["eth_address"].startswith("0x")
    assert info["did"].startswith("did:ethr:0x")


# ══════════════════════════════════════════════════════════════════════════════
# 7. VAULT-LEVEL IDENTITY METHODS
# ══════════════════════════════════════════════════════════════════════════════

def test_vault_create_identity(tmp_path):
    with Vault(PASS_A, tmp_path / "test.db") as v:
        info = v.create_identity()
    assert "did" in info
    assert info["did"].startswith("did:ethr:0x")


def test_vault_get_identity_before_keygen_returns_none(tmp_path):
    with Vault(PASS_A, tmp_path / "test.db") as v:
        assert v.get_identity() is None


def test_vault_get_identity_after_keygen(tmp_path):
    with Vault(PASS_A, tmp_path / "test.db") as v:
        created = v.create_identity()
        fetched = v.get_identity()
    assert fetched is not None
    assert fetched["did"] == created["did"]
    assert fetched["eth_address"] == created["eth_address"]


def test_vault_create_identity_idempotent(tmp_path):
    """Running keygen twice produces the same DID."""
    with Vault(PASS_A, tmp_path / "test.db") as v:
        info1 = v.create_identity()
        info2 = v.create_identity()
    assert info1["did"] == info2["did"]
    assert info1["public_key_hex"] == info2["public_key_hex"]


def test_vault_sign_message(tmp_path):
    with Vault(PASS_A, tmp_path / "test.db") as v:
        v.create_identity()
        sig = v.sign_message(MESSAGE)
    assert len(sig) == 65


def test_vault_sign_without_keygen_raises(tmp_path):
    with Vault(PASS_A, tmp_path / "test.db") as v:
        with pytest.raises(ValueError, match="keygen"):
            v.sign_message(MESSAGE)


def test_vault_sign_verify_roundtrip(tmp_path):
    with Vault(PASS_A, tmp_path / "test.db") as v:
        info = v.create_identity()
        sig  = v.sign_message(MESSAGE)
        ok   = v.verify_signature(MESSAGE, sig, info["public_key_hex"])
    assert ok is True


def test_vault_verify_wrong_key_fails(tmp_path):
    db_a = tmp_path / "a.db"
    db_b = tmp_path / "b.db"
    with Vault(PASS_A, db_a) as va:
        info_a = va.create_identity()
        sig_a  = va.sign_message(MESSAGE)
    with Vault(PASS_B, db_b) as vb:
        info_b = vb.create_identity()
        ok = vb.verify_signature(MESSAGE, sig_a, info_b["public_key_hex"])
    assert ok is False


def test_vault_different_passphrases_different_dids(tmp_path):
    db_a = tmp_path / "a.db"
    db_b = tmp_path / "b.db"
    with Vault(PASS_A, db_a) as va:
        info_a = va.create_identity()
    with Vault(PASS_B, db_b) as vb:
        info_b = vb.create_identity()
    assert info_a["did"] != info_b["did"]
