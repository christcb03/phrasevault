# phrasevault/server.py
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import uuid
from . import vault, store
from .credentials import CommunityCredential

app = FastAPI(title="PhraseVault Relay Server")

class QueryRequest(BaseModel):
    credential: str          # JWT
    community_pubkey_pem: str
    query_text: str
    topic: str | None = None

class StoreRequest(BaseModel):
    ciphertext: str
    address: str
    owner_did: str

@app.post("/store")
async def store_blob(req: StoreRequest):
    """Dumb relay: just store encrypted blob"""
    conn = store.open_db()
    # TODO: add metadata table for address → owner + access_rules
    conn.execute("INSERT OR REPLACE INTO entries (address, ciphertext, owner_did) VALUES (?, ?, ?)",
                 (req.address, req.ciphertext, req.owner_did))
    conn.commit()
    conn.close()
    return {"status": "stored", "address": req.address}

@app.post("/query")
async def queue_query(req: QueryRequest):
    """Queue a query for the owner's client to evaluate"""
    claims = CommunityCredential.verify(req.credential, req.community_pubkey_pem)
    
    query_id = str(uuid.uuid4())
    # TODO: store in a queries table with status="pending"
    # For now we just return the ID — client will poll
    return {
        "query_id": query_id,
        "status": "queued",
        "claims": claims.__dict__
    }

# Health + basic info
@app.get("/health")
async def health():
    return {"status": "ok", "server": "dumb relay"}
