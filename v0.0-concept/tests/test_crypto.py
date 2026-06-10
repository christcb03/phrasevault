"""Tests for phrasevault.crypto — pure crypto primitives, zero I/O."""
import math
import pytest
from phrasevault.crypto import (
    derive_address, derive_key, encrypt_payload, decrypt_payload,
    chain_address, pi_checkpoint, impossibility_measure, effective_score,
    pack_timestamp,
)

PASS = "correct horse battery staple"
TS   = 1_700_000_000_000_000_000


def test_derive_address_32_bytes():
    assert len(derive_address(PASS, 0)) == 32

def test_derive_address_deterministic():
    assert derive_address(PASS, 0) == derive_address(PASS, 0)

def test_derive_address_position_changes():
    assert derive_address(PASS, 0) != derive_address(PASS, 1)

def test_derive_address_passphrase_changes():
    assert derive_address(PASS, 0) != derive_address("other words here test", 0)

def test_derive_key_32_bytes():
    assert len(derive_key(PASS, TS, 0)) == 32

def test_derive_key_deterministic():
    assert derive_key(PASS, TS, 0) == derive_key(PASS, TS, 0)

def test_derive_key_differs_from_address():
    assert derive_address(PASS, 0) != derive_key(PASS, TS, 0)

def test_derive_key_timestamp_changes():
    assert derive_key(PASS, TS, 0) != derive_key(PASS, TS + 1, 0)

def test_encrypt_decrypt_roundtrip():
    key = derive_key(PASS, TS, 0)
    plaintext = b"water boils at 100C"
    nonce, ct = encrypt_payload(key, plaintext)
    assert decrypt_payload(key, nonce, ct) == plaintext

def test_encrypt_nonce_is_random():
    key = derive_key(PASS, TS, 0)
    n1, _ = encrypt_payload(key, b"same")
    n2, _ = encrypt_payload(key, b"same")
    assert n1 != n2

def test_decrypt_wrong_key_raises():
    k1 = derive_key(PASS, TS, 0)
    k2 = derive_key("wrong passphrase words here", TS, 0)
    nonce, ct = encrypt_payload(k1, b"secret")
    with pytest.raises(Exception):
        decrypt_payload(k2, nonce, ct)

def test_chain_address_32_bytes():
    prev = derive_address(PASS, 0)
    assert len(chain_address(prev, PASS, 1)) == 32

def test_chain_address_prev_matters():
    p1 = derive_address(PASS, 0)
    p2 = derive_address("other words here test", 0)
    assert chain_address(p1, PASS, 1) != chain_address(p2, PASS, 1)

def test_pi_checkpoint_16_bytes():
    assert len(pi_checkpoint(0)) == 16

def test_pi_checkpoint_deterministic():
    assert pi_checkpoint(5) == pi_checkpoint(5)

def test_pi_checkpoint_position_changes():
    assert pi_checkpoint(0) != pi_checkpoint(1)

def test_impossibility_measure_zero():
    assert impossibility_measure(0.0) == 0.0

def test_impossibility_measure_formula():
    score = 0.5
    assert abs(impossibility_measure(score) - (-math.log(0.5))) < 1e-12

def test_impossibility_measure_known():
    assert abs(impossibility_measure(0.05) - 0.05129329438755058) < 1e-9
    assert abs(impossibility_measure(0.79) - 1.5606477482646693) < 1e-9

def test_effective_score_no_anchors():
    assert effective_score(0.5, []) == 0.5

def test_effective_score_pulls_down():
    assert effective_score(0.5, [0.1]) < 0.5

def test_effective_score_higher_anchor_ignored():
    assert effective_score(0.5, [0.9]) == 0.5

def test_pack_timestamp_8_bytes():
    assert len(pack_timestamp(TS)) == 8
