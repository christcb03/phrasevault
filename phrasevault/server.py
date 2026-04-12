"""
PhraseVault API server — FastAPI application.

The server is a dumb encrypted blob store. It never sees passphrases.
Clients encrypt before sending, decrypt after receiving.

Endpoints:
  GET  /health              — liveness check
  GET  /ready               — readiness check (DB accessible)
  PUT  /entry/{address}     — store an encrypted blob
  GET  /entry/{address}     — retrieve an encrypted blob
  GET  /entries             — list all addresses (no blobs)
  GET  /sync/info           — chain summary for peer sync
  GET  /forest/fingerprint  — current T33 forest fingerprint
  POST /forest/import       — import a forest JSON (unencrypted layer)

Authentication: X-API-Key header. Set PV_API_KEY env var on the server.
If PV_API_KEY is unset, the server refuses all requests (fail-safe).
"""

import os
import json
import logging
import sqlite3
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Header, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from phrasevault import store, transfer, forest

# ─── Configuration ────────────────────────────────────────────────────────────

DB_PATH  = Path(os.environ.get("PV_DB_PATH",  "/data/phrasevault.db"))
API_KEY  = os.environ.get("PV_API_KEY", "")
LOG_LEVEL = os.environ.get("PV_LOG_LEVEL", "INFO")

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("phrasevault.server")

if not API_KEY:
    log.error("PV_API_KEY is not set — all requests will be rejected. Set it before starting.")

app = FastAPI(
    title="PhraseVault",
    description="Distributed encrypted knowledge network. Blobs only — no passphrases.",
    version="0.1.0",
    docs_url="/docs" if os.environ.get("PV_DOCS", "0") == "1" else None,
)

# ─── DB connection (one per process, WAL mode handles concurrency) ────────────

_conn: sqlite3.Connection | None = None

def get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = store.open_db(DB_PATH)
        store.init_schema(_conn)
        log.info("Database opened at %s", DB_PATH)
    return _conn

# ─── Auth ─────────────────────────────────────────────────────────────────────

def require_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
    """Dependency — raises 401 if key missing or wrong."""
    if not API_KEY:
        raise HTTPException(status_code=503, detail="Server not configured (PV_API_KEY unset)")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")

# ─── Models ───────────────────────────────────────────────────────────────────

class EntryPayload(BaseModel):
    """Encrypted blob sent by client. Server stores it verbatim."""
    nonce:          str   # base64
    ciphertext:     str   # base64
    chain_position: int
    prev_address:   str | None = None
    pi_checkpoint:  str        # base64
    bundle_sha256:  str        # integrity hash
    timestamp_ns:   int
    confidence:     float
    shell:          int = 3

class ForestImportPayload(BaseModel):
    """Raw forest JSON as a string."""
    forest_json: str

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
async def health():
    return {"status": "ok"}

@app.get("/ready", tags=["ops"])
async def ready():
    try:
        conn = get_conn()
        conn.execute("SELECT 1")
        return {"status": "ready", "db": str(DB_PATH)}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"DB not ready: {e}")

@app.put("/entry/{address}", tags=["entries"])
async def put_entry(
    address: str,
    payload: EntryPayload,
    x_api_key: Annotated[str | None, Header()] = None,
):
    require_api_key(x_api_key)
    if len(address) != 64 or not all(c in "0123456789abcdef" for c in address):
        raise HTTPException(status_code=400, detail="address must be 64 hex chars")
    conn = get_conn()
    # Check for duplicate
    existing = conn.execute(
        "SELECT address FROM entries WHERE address = ?", (address,)
    ).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="Entry already exists")
    try:
        import base64
        store.insert_entry(
            conn           = conn,
            address        = bytes.fromhex(address),
            chain_position = payload.chain_position,
            prev_address   = bytes.fromhex(payload.prev_address) if payload.prev_address else None,
            nonce          = base64.b64decode(payload.nonce),
            ciphertext     = base64.b64decode(payload.ciphertext),
            timestamp_ns   = payload.timestamp_ns,
            confidence     = payload.confidence,
            shell          = payload.shell,
            pi_checkpoint  = base64.b64decode(payload.pi_checkpoint),
        )
        conn.commit()
        log.info("PUT /entry/%s  position=%d", address[:16], payload.chain_position)
        return {"stored": address}
    except Exception as e:
        log.error("PUT /entry/%s failed: %s", address[:16], e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/entry/{address}", tags=["entries"])
async def get_entry(
    address: str,
    x_api_key: Annotated[str | None, Header()] = None,
):
    require_api_key(x_api_key)
    if len(address) != 64 or not all(c in "0123456789abcdef" for c in address):
        raise HTTPException(status_code=400, detail="address must be 64 hex chars")
    conn = get_conn()
    row = store.fetch_entry_by_address(conn, bytes.fromhex(address))
    if row is None:
        raise HTTPException(status_code=404, detail="Entry not found")
    import base64
    return {
        "address":        address,
        "nonce":          base64.b64encode(bytes(row["nonce"])).decode(),
        "ciphertext":     base64.b64encode(bytes(row["ciphertext"])).decode(),
        "chain_position": row["chain_position"],
        "prev_address":   bytes(row["prev_address"]).hex() if row["prev_address"] else None,
        "pi_checkpoint":  base64.b64encode(bytes(row["pi_checkpoint"])).decode(),
        "timestamp_ns":   row["timestamp_ns"],
        "confidence":     row["confidence"],
        "shell":          row["shell"],
    }

@app.get("/entries", tags=["entries"])
async def list_entries(
    x_api_key: Annotated[str | None, Header()] = None,
):
    require_api_key(x_api_key)
    conn = get_conn()
    rows = conn.execute(
        "SELECT address, chain_position, confidence, shell, timestamp_ns, superseded "
        "FROM entries ORDER BY chain_position"
    ).fetchall()
    return {
        "count": len(rows),
        "entries": [
            {
                "address":        bytes(r["address"]).hex(),
                "chain_position": r["chain_position"],
                "confidence":     r["confidence"],
                "shell":          r["shell"],
                "timestamp_ns":   r["timestamp_ns"],
                "superseded":     bool(r["superseded"]),
            }
            for r in rows
        ],
    }

@app.get("/sync/info", tags=["sync"])
async def sync_info(
    x_api_key: Annotated[str | None, Header()] = None,
):
    require_api_key(x_api_key)
    conn = get_conn()
    info = transfer.sync_summary(conn)
    return info

@app.get("/forest/fingerprint", tags=["forest"])
async def get_fingerprint(
    x_api_key: Annotated[str | None, Header()] = None,
):
    require_api_key(x_api_key)
    conn = get_conn()
    fp = forest.forest_fingerprint(conn)
    return {"fingerprint": fp}

@app.post("/forest/import", tags=["forest"])
async def import_forest(
    payload: ForestImportPayload,
    x_api_key: Annotated[str | None, Header()] = None,
):
    require_api_key(x_api_key)
    import tempfile
    conn = get_conn()
    # Write JSON to a temp file then import
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(payload.forest_json)
        tmp_path = f.name
    try:
        result = forest.import_forest_to_db(tmp_path, conn=conn)
        log.info("forest/import: inserted=%d updated=%d fingerprint=%s",
                 result["inserted"], result["updated"], result["fingerprint"][:16])
        return result
    except Exception as e:
        log.error("forest/import failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        os.unlink(tmp_path)

# ─── Error handler ────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_handler(request: Request, exc: Exception):
    log.error("Unhandled error on %s %s: %s", request.method, request.url, exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
