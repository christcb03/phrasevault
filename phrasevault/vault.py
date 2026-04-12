"""
phrasevault/vault.py
────────────────────
The public API.  Combines crypto.py + store.py into clean, sequential steps.
Each public function walks through the pipeline in order and names every step
so stack traces are self-explanatory.

Triplet format (what gets encrypted):
  {
    "subject":    str,
    "predicate":  str,
    "object":     str,
    "confidence": float,   # [0.0, 1.0)
    "shell":      int,     # prime shell: 1, 3, 5, 7, 11 …
    "timestamp_ns": int,   # set at store time; baked into key
    "node_id":    str,     # e.g. "T8_Entropy_Confidence_Identity"
    "links":      list[str],
    "node_type":  str,
    "supersedes": str | None,   # node_id of entry this corrects (T30)
  }
"""

import json
from pathlib import Path
from typing import Any

from . import crypto, store


# ══════════════════════════════════════════════════════════════════════════════
# VAULT CLASS
# Thin wrapper that holds a DB connection and a passphrase slot label.
# One Vault = one passphrase = one chain.
# ══════════════════════════════════════════════════════════════════════════════

class Vault:
    def __init__(self, passphrase: str, db_path: Path = store.DEFAULT_DB):
        """
        Open (or create) a vault.
        The passphrase is held in memory for the lifetime of this object.
        It is never written to disk.
        """
        self.passphrase = passphrase
        self.conn       = store.open_db(db_path)
        store.init_schema(self.conn)

        # Slot = first 16 hex chars of BLAKE3(passphrase).
        # Identifies the chain in chain_heads without revealing the passphrase.
        slot_raw   = crypto.derive_address(passphrase, 0)
        self.slot  = slot_raw.hex()[:16]

    # ─── internal helpers ─────────────────────────────────────────────────

    def _next_position(self) -> tuple[int, bytes]:
        """Return (next_chain_position, prev_address)."""
        head = store.fetch_chain_head(self.conn, self.slot)
        if head is None:
            # Genesis entry
            return 0, bytes(32)                         # prev = 32 zero bytes
        return head["head_position"] + 1, bytes(head["head_address"])

    # ─── public API ───────────────────────────────────────────────────────

    def store_triplet(
        self,
        subject:    str,
        predicate:  str,
        object_:    str,
        confidence: float,
        shell:      int  = 3,
        node_id:    str  = "",
        links:      list | None = None,
        node_type:  str  = "",
        supersedes: str | None  = None,
    ) -> str:
        """
        Encrypt one RDF triplet and write it to the local DB.
        Returns the hex address (use this to retrieve later).

        Pipeline (each step independent, testable):
          1. Capture timestamp
          2. Get next chain position + prev_address
          3. Derive chained storage address  (BLAKE3)
          4. Derive encryption key           (Argon2id — slow ~1s)
          5. Build plaintext payload         (JSON)
          6. Encrypt payload                 (XSalsa20-Poly1305)
          7. Compute pi checkpoint           (fast)
          8. Write to SQLite                 (atomic)
          9. Update chain head               (atomic)
        """
        # Step 1 — timestamp (baked into key; unforgeable ordering)
        timestamp_ns = crypto.now_ns()

        # Step 2 — chain position
        position, prev_address = self._next_position()

        # Step 3 — storage address (fast)
        address = crypto.chain_address(prev_address, self.passphrase, position)

        # Step 4 — encryption key (slow — Argon2id, ~1 second)
        key = crypto.derive_key(self.passphrase, timestamp_ns, position)

        # Step 5 — build plaintext as JSON
        payload = {
            "subject":      subject,
            "predicate":    predicate,
            "object":       object_,
            "confidence":   confidence,
            "shell":        shell,
            "timestamp_ns": timestamp_ns,
            "node_id":      node_id,
            "links":        links or [],
            "node_type":    node_type,
            "supersedes":   supersedes,
            "impossibility_measure": crypto.impossibility_measure(confidence),
        }
        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        # Step 6 — encrypt
        nonce, ciphertext = crypto.encrypt_payload(key, plaintext)

        # Step 7 — pi checkpoint
        pi_chk = crypto.pi_checkpoint(position)

        # Step 8 — write entry
        store.insert_entry(
            conn           = self.conn,
            address        = address,
            chain_position = position,
            prev_address   = prev_address if position > 0 else None,
            nonce          = nonce,
            ciphertext     = ciphertext,
            timestamp_ns   = timestamp_ns,
            confidence     = confidence,
            shell          = shell,
            pi_checkpoint  = pi_chk,
        )

        # Step 9 — update chain head
        store.update_chain_head(self.conn, self.slot, address, position)

        # If this supersedes a prior entry, mark that entry superseded (T30)
        if supersedes:
            prior_addr = self._find_address_by_node_id(supersedes)
            if prior_addr:
                store.mark_superseded(self.conn, prior_addr)

        return address.hex()

    def retrieve_triplet(self, address_hex: str) -> dict[str, Any]:
        """
        Fetch and decrypt one entry by its hex address.
        Returns the original triplet dict.
        Raises KeyError if address not found.
        Raises nacl.exceptions.CryptoError if decryption fails (wrong passphrase).

        Pipeline:
          1. Look up row by address            (SQLite)
          2. Derive encryption key             (Argon2id — slow ~1s)
          3. Decrypt ciphertext                (XSalsa20-Poly1305)
          4. Parse JSON                        (fast)
          5. Attach effective score            (fast)
        """
        address = bytes.fromhex(address_hex)

        # Step 1 — fetch row
        row = store.fetch_entry(self.conn, address)
        if row is None:
            raise KeyError(f"No entry at address {address_hex}")

        # Step 2 — re-derive key using stored timestamp + position
        key = crypto.derive_key(
            self.passphrase,
            row["timestamp_ns"],
            row["chain_position"],
        )

        # Step 3 — decrypt
        plaintext = crypto.decrypt_payload(key, bytes(row["nonce"]), bytes(row["ciphertext"]))

        # Step 4 — parse
        triplet = json.loads(plaintext.decode("utf-8"))

        # Step 5 — attach live effective score if possible (no anchors yet without graph)
        triplet["stored_score"]  = triplet["confidence"]
        triplet["address"]       = address_hex
        triplet["superseded"]    = bool(row["superseded"])
        return triplet

    def list_entries(self, include_superseded: bool = False) -> list[dict]:
        """
        Return metadata (no decryption) for all entries, sorted by confidence.
        Fast — never touches Argon2id.
        """
        rows = store.fetch_entries_by_confidence(
            self.conn, include_superseded=include_superseded
        )
        return [
            {
                "address":        bytes(r["address"]).hex(),
                "chain_position": r["chain_position"],
                "timestamp_ns":   r["timestamp_ns"],
                "confidence":     r["confidence"],
                "shell":          r["shell"],
                "superseded":     bool(r["superseded"]),
            }
            for r in rows
        ]

    def entry_count(self) -> int:
        """Total non-superseded entries in this vault."""
        return store.count_entries(self.conn)

    # ─── internal helpers ─────────────────────────────────────────────────

    def _find_address_by_node_id(self, node_id: str) -> bytes | None:
        """
        Scan entries for one whose decrypted payload has matching node_id.
        Only used for supersession (T30) — intentionally slow to prevent abuse.
        Returns None if not found (non-fatal; supersede is best-effort).
        """
        rows = store.fetch_all_entries(self.conn, include_superseded=True)
        for row in rows:
            try:
                key = crypto.derive_key(
                    self.passphrase,
                    row["timestamp_ns"],
                    row["chain_position"],
                )
                pt = crypto.decrypt_payload(
                    key, bytes(row["nonce"]), bytes(row["ciphertext"])
                )
                data = json.loads(pt.decode("utf-8"))
                if data.get("node_id") == node_id:
                    return bytes(row["address"])
            except Exception:
                continue
        return None

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
