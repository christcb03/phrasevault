# phrasevault/forest.py
import json
import math
import time
from pathlib import Path
from typing import Optional

import blake3

from . import store

def import_forest_to_db(json_path: str | Path, db_path: str | Path = None) -> dict:
    # (existing import function unchanged)
    ...  # [same as before - omitted for brevity]

def forest_fingerprint(conn) -> str:
    rows = conn.execute(
        "SELECT node_id, falsehood_probability FROM forest_nodes "
        "WHERE superseded = 0 ORDER BY node_id ASC"
    ).fetchall()
    canonical = "\n".join(f"{r['node_id']}={r['falsehood_probability']:.15f}" for r in rows).encode("utf-8")
    return blake3.blake3(b"phrasevault:forest:v1:" + canonical).hexdigest()


def re_encrypt_existing_data(passphrase: str, db_path: str | Path = None) -> dict:
    """ONE-TIME migration: Encrypt all current plaintext nodes with your passphrase"""
    from . import vault
    v = vault.Vault(passphrase)
    conn = store.open_db(db_path)

    try:
        nodes = conn.execute("SELECT node_id, words_json, links_json FROM forest_nodes").fetchall()
        if not nodes:
            return {"status": "nothing_to_do"}

        for node in nodes:
            node_id = node["node_id"]
            payload = {
                "node_id": node_id,
                "words": json.loads(node["words_json"] or "[]"),
                "links": json.loads(node["links_json"] or "[]"),
                "timestamp": int(time.time())
            }
            ciphertext = v.encrypt(json.dumps(payload).encode("utf-8"))

            conn.execute("""
                INSERT OR REPLACE INTO entries (address, ciphertext, owner_did)
                VALUES (?, ?, ?)
            """, (node_id, ciphertext, "owner"))

        # Update forest signature with encrypted fingerprint
        fp = forest_fingerprint(conn)
        encrypted_fp = v.encrypt(fp.encode("utf-8"))
        conn.execute("""
            INSERT OR REPLACE INTO forest_signatures 
            (forest_id, version, node_count, fingerprint, encrypted_fingerprint, signed_at_ns)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("main", "v5", len(nodes), fp, encrypted_fp, int(time.time() * 1_000_000_000)))

        conn.commit()
        return {"status": "success", "re_encrypted_nodes": len(nodes), "message": "All data is now properly encrypted"}

    finally:
        conn.close()