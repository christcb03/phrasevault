"""Tests for phrasevault.vault — store and retrieve triplets end-to-end."""
import pytest
from phrasevault.vault import Vault

PASS = "correct horse battery staple"


@pytest.fixture
def vault(tmp_path):
    return Vault(PASS, str(tmp_path / "test.db"))


def test_store_returns_hex_address(vault):
    addr = vault.store_triplet("water", "boils_at", "100C", 0.05)
    assert isinstance(addr, str) and len(addr) == 64

def test_roundtrip(vault):
    addr = vault.store_triplet("water", "boils_at", "100C at sea level", 0.05)
    r = vault.retrieve_triplet(addr)
    assert r["subject"] == "water"
    assert r["predicate"] == "boils_at"
    assert r["object"] == "100C at sea level"

def test_wrong_passphrase_raises(vault, tmp_path):
    addr = vault.store_triplet("water", "boils_at", "100C", 0.05)
    wrong = Vault("wrong passphrase words fail", str(tmp_path / "test.db"))
    with pytest.raises(Exception):
        wrong.retrieve_triplet(addr)

def test_multiple_entries_chain(vault):
    a0 = vault.store_triplet("water", "boils_at", "100C", 0.05)
    a1 = vault.store_triplet("ice", "melts_at", "0C", 0.05)
    assert vault.retrieve_triplet(a0)["subject"] == "water"
    assert vault.retrieve_triplet(a1)["subject"] == "ice"

def test_retrieve_missing_address_raises(vault):
    with pytest.raises(Exception):
        vault.retrieve_triplet("0" * 64)
