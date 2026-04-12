"""
phrasevault/transfer.py
────────────────────────
Inter-instance data transfer — how encrypted entries move between nodes.

Design principle: the encrypted blob is ALREADY safe to transmit.
Only the passphrase holder can decrypt it.  So "transfer" means:
  1. Serialize the raw DB row (address, nonce, ciphertext, metadata) to JSON
  2. Transmit by ANY means (file, socket, clipboard, QR code, email…)
  3. Import at the receiving end → write to local SQLite
  4. Receiver uses their passphrase to decrypt (must match sender's)

This implements the "partial chain handshake" from the architecture:
  - Each bundle carries its chain_position + prev_address
  - Receiver can verify continuity before importing
  - Timestamp in the key means ordering is cryptographically unforgeable

Transfer formats:
  .pvx   — PhraseVault eXchange: newline-delimited JSON (one object per line)
           Easy to cat, grep, append, and stream.
  dict   — in-memory dict for direct instance-to-instance calls (same process)
"""

import json
import base64
import hashlib
from pathlib import Path
from typing import Any

from . import store, crypto


# ══════════════════════════════════════════════════════════════════════════════
# EXPORT — serialize one or more entries for transfer
# ══════════════════════════════════════════════════════════════════════════════

def export_entry(conn, address_hex: str) -> dict[str, Any]:
    """
    Serialize one entry (by address) to a transfer-safe dict.
    The ciphertext and nonce are base64-encoded for JSON safety.
    No decryption occurs — the blob is opaque to the exporter.

    Returns a dict with everything the importer needs to:
      - write the row to their DB       (address, nonce, ciphertext, metadata)
      - verify chain continuity         (chain_position, prev_address)
      - verify pi checkpoint            (pi_checkpoint)
      - verify the bundle hash          (bundle_sha256)
    """
    address = bytes.fromhex(address_hex)
    row = store.fetch_entry(conn, address)
    if row is None:
        raise KeyError(f"No entry at address {address_hex}")

    bundle = {
        "pvx_version":    "1.0",
        "address":        address_hex,
        "chain_position": row["chain_position"],
        "prev_address":   bytes(row["prev_address"]).hex() if row["prev_address"] else None,
        "nonce":          base64.b64encode(bytes(row["nonce"])).decode(),
        "ciphertext":     base64.b64encode(bytes(row["ciphertext"])).decode(),
        "timestamp_ns":   row["timestamp_ns"],
        "confidence":     row["confidence"],
        "shell":          row["shell"],
        "superseded":     bool(row["superseded"]),
        "pi_checkpoint":  bytes(row["pi_checkpoint"]).hex() if row["pi_checkpoint"] else None,
        "origin_instance": row["origin_instance"],
    }

    # Integrity hash of the bundle itself (SHA-256 of canonical JSON)
    # Receiver verifies this before importing.
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    bundle["bundle_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()

    return bundle


def export_all(conn, output_path: Path, include_superseded: bool = False) -> int:
    """
    Export all entries to a .pvx file (newline-delimited JSON).
    Returns the number of entries written.

    The file is safe to share — all payloads are encrypted.
    Append mode not used: always writes a fresh export.
    """
    rows = store.fetch_all_entries(conn, include_superseded=include_superseded)
    count = 0
    with open(output_path, "w", encoding="utf-8") as f:
        for row in rows:
            bundle = export_entry(conn, bytes(row["address"]).hex())
            f.write(json.dumps(bundle, separators=(",", ":")) + "\n")
            count += 1
    return count


def export_since(conn, after_position: int, output_path: Path) -> int:
    """
    Export only entries with chain_position > after_position.
    Use this for incremental sync: receiver tracks the last position they have,
    sender exports only what's newer.  This is the "partial chain handshake".
    """
    rows = conn.execute(
        "SELECT * FROM entries WHERE chain_position > ? AND superseded = 0"
        " ORDER BY chain_position ASC",
        (after_position,),
    ).fetchall()
    count = 0
    with open(output_path, "w", encoding="utf-8") as f:
        for row in rows:
            bundle = export_entry(conn, bytes(row["address"]).hex())
            f.write(json.dumps(bundle, separators=(",", ":")) + "\n")
            count += 1
    return count


# ══════════════════════════════════════════════════════════════════════════════
# IMPORT — verify and write received entries to local DB
# ══════════════════════════════════════════════════════════════════════════════

class IntegrityError(Exception):
    """Raised when a received bundle fails integrity checks."""


def verify_bundle(bundle: dict[str, Any]) -> None:
    """
    Verify the bundle_sha256 and pi_checkpoint before importing.
    Raises IntegrityError with a descriptive message on failure.
    This is the FIRST thing import_entry calls — reject bad data early.
    """
    # Step 1 — extract and remove the hash from the bundle
    received_hash = bundle.pop("bundle_sha256", None)
    if received_hash is None:
        raise IntegrityError("Bundle missing bundle_sha256 field")

    # Step 2 — recompute hash over remaining fields
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    computed  = hashlib.sha256(canonical.encode()).hexdigest()

    if received_hash != computed:
        raise IntegrityError(
            f"Bundle SHA-256 mismatch.\n"
            f"  received: {received_hash}\n"
            f"  computed: {computed}"
        )

    # Step 3 — put the hash back (don't mutate caller's dict permanently)
    bundle["bundle_sha256"] = received_hash

    # Step 4 — pi checkpoint verification
    if bundle.get("pi_checkpoint"):
        position      = bundle["chain_position"]
        expected_pi   = crypto.pi_checkpoint(position).hex()
        received_pi   = bundle["pi_checkpoint"]
        if received_pi != expected_pi:
            raise IntegrityError(
                f"Pi checkpoint mismatch at position {position}.\n"
                f"  received: {received_pi}\n"
                f"  expected: {expected_pi}"
            )


def import_entry(
    conn,
    bundle: dict[str, Any],
    origin_instance: str = "unknown",
    skip_if_exists: bool = True,
) -> str:
    """
    Verify and import one bundle into the local database.
    Returns the address_hex of the imported entry.
    Raises IntegrityError if verification fails.
    Raises sqlite3.IntegrityError if address already exists (and skip_if_exists=False).

    Pipeline:
      1. Verify bundle SHA-256          (tamper detection)
      2. Verify pi checkpoint           (dual-layer tamper detection)
      3. Decode base64 nonce+ciphertext (no decryption needed)
      4. Write to local SQLite          (atomic)
    """
    # Step 1+2 — verify before touching the DB
    verify_bundle(bundle)

    address_hex = bundle["address"]
    address     = bytes.fromhex(address_hex)

    # Step 3 — skip if already present
    if skip_if_exists and store.fetch_entry(conn, address) is not None:
        return address_hex

    # Step 4 — decode and write
    store.insert_entry(
        conn           = conn,
        address        = address,
        chain_position = bundle["chain_position"],
        prev_address   = bytes.fromhex(bundle["prev_address"]) if bundle["prev_address"] else None,
        nonce          = base64.b64decode(bundle["nonce"]),
        ciphertext     = base64.b64decode(bundle["ciphertext"]),
        timestamp_ns   = bundle["timestamp_ns"],
        confidence     = bundle["confidence"],
        shell          = bundle["shell"],
        pi_checkpoint  = bytes.fromhex(bundle["pi_checkpoint"]) if bundle["pi_checkpoint"] else None,
        origin_instance= origin_instance,
    )
    return address_hex


def import_file(
    conn,
    input_path: Path,
    origin_instance: str = "file",
    skip_if_exists: bool = True,
) -> tuple[int, int]:
    """
    Import all entries from a .pvx file.
    Returns (imported_count, skipped_count).

    Each line is verified independently — a bad line is skipped with a warning,
    not a fatal error, so a partially corrupt file still imports the good entries.
    """
    imported = 0
    skipped  = 0
    with open(input_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                bundle = json.loads(line)
                import_entry(conn, bundle, origin_instance=origin_instance,
                             skip_if_exists=skip_if_exists)
                imported += 1
            except IntegrityError as e:
                print(f"[transfer] Line {line_num}: INTEGRITY FAIL — {e}")
                skipped += 1
            except Exception as e:
                print(f"[transfer] Line {line_num}: ERROR — {e}")
                skipped += 1
    return imported, skipped


# ══════════════════════════════════════════════════════════════════════════════
# SYNC HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def latest_position(conn) -> int:
    """Return the highest chain_position in the local DB (-1 if empty)."""
    row = conn.execute(
        "SELECT MAX(chain_position) as mp FROM entries WHERE superseded = 0"
    ).fetchone()
    return row["mp"] if row["mp"] is not None else -1


def sync_summary(conn) -> dict:
    """
    Return a dict describing the current state of this instance.
    Share this with a peer so they know what to send you.
    Contains NO sensitive data — just chain position and entry count.
    """
    return {
        "latest_position": latest_position(conn),
        "entry_count":     store.count_entries(conn),
        "pvx_version":     "1.0",
    }
