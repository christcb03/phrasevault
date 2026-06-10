# phrasevault/server.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uuid
from typing import List

from .credentials import CommunityCredential

app = FastAPI(title="PhraseVault Relay Server")

pending_queries: List[dict] = []

class QueryRequest(BaseModel):
    credential: str
    community_pubkey_pem: str
    query_text: str
    topic: str | None = None

@app.on_event("startup")
async def startup_event():
    print("\n" + "="*70)
    print("🚀 PhraseVault Server started successfully")
    print("   Listening on http://0.0.0.0:8000")
    print("   Ready to receive queries from clients")
    print("   (Polling is silenced)")
    print("="*70 + "\n")

@app.post("/query")
async def queue_query(req: QueryRequest):
    try:
        claims = CommunityCredential.verify(req.credential, req.community_pubkey_pem)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    query_id = str(uuid.uuid4())
    pending_queries.append({
        "query_id": query_id,
        "credential": req.credential,
        "community_pubkey_pem": req.community_pubkey_pem,
        "query_text": req.query_text,
        "topic": req.topic
    })

    print(f"📬 Query queued → ID: {query_id}")
    return {"query_id": query_id, "status": "queued"}

@app.get("/queries/pending")
async def get_pending_queries():
    return {"queries": pending_queries}

@app.delete("/query/{query_id}")
async def remove_query(query_id: str):
    global pending_queries
    original_len = len(pending_queries)
    pending_queries = [q for q in pending_queries if q["query_id"] != query_id]
    if len(pending_queries) < original_len:
        print(f"🗑️  Query {query_id} removed from queue")
    return {"status": "removed"}

@app.delete("/queries/clear")
async def clear_all_queries():
    global pending_queries
    pending_queries.clear()
    print("🧹 All pending queries cleared")
    return {"status": "cleared"}

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="critical",
        access_log=False,
        log_config=None
    )