# phrasevault/vault.py
"""
Passphrase-first encrypted storage for PhraseVault
Uses Argon2id + XSalsa20-Poly1305 + BLAKE3
"""

import getpass
import time
from pathlib import Path

import argon2
from argon2.low_level import hash_secret_raw, Type
import blake3
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError

class Vault:
    def __init__(self, passphrase: str | None = None):
        if passphrase is None:
            passphrase = getpass.getpass("Passphrase: ")
        self.passphrase = passphrase.encode("utf-8")
        self._derive_key()

    def _derive_key(self):
        """Derive a proper 32-byte raw key from passphrase (slow on purpose)"""
        print("   [DEBUG] Deriving encryption key from passphrase (Argon2id)...")
        start = time.time()

        # Use low-level API to get exactly 32 raw bytes
        self.key = hash_secret_raw(
            secret=self.passphrase,
            salt=b"phrasevault_salt_32b",   # fixed salt for determinism
            time_cost=2,
            memory_cost=1024 * 64,          # 64 MiB
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )

        print(f"   [DEBUG] Key derived in {time.time() - start:.1f}s")

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data with XSalsa20-Poly1305"""
        box = SecretBox(self.key)
        return box.encrypt(data)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data — raises if passphrase is wrong"""
        try:
            box = SecretBox(self.key)
            return box.decrypt(ciphertext)
        except CryptoError:
            raise ValueError("Decryption failed — wrong passphrase or corrupted data")

    def get_address(self, data: bytes) -> str:
        """BLAKE3 address for storage"""
        return blake3.blake3(data).hexdigest()