# phrasevault/client.py
from . import vault, forest, credentials
import asyncio

class PhraseVaultClient:
    def __init__(self, passphrase: str):
        self.vault = vault.Vault(passphrase)
        self.identity = None  # loaded on first use

    async def evaluate_queued_queries(self):
        """Client-side query evaluation loop"""
        # TODO: poll server /query queue for this owner
        # For now: simulate one query
        print("🔍 Client evaluating queued queries...")

        # Example: pull a query, decrypt forest, run search
        # forest.verify_file(...) and forest.search() would go here
        # Return encrypted answer only if rules pass
        print("✅ Query evaluated locally — response ready")

# phrasevault/client.py
"""
PhraseVault Client - Privacy-first query evaluator
Runs locally on the user's machine (laptop, mediabox, etc.)
- Holds the passphrase / secp256k1 identity
- Polls the dumb relay server for queued queries
- Decrypts forest locally
- Evaluates queries using forest.py
- Returns encrypted responses only if access rules pass
"""

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional

import httpx
from pydantic import BaseModel

from . import vault, forest, credentials, store
from .credentials import CommunityCredential, CredentialClaims


class QueryRequest(BaseModel):
    """Incoming query from the server"""
    query_id: str
    credential: str                    # JWT from requester
    community_pubkey_pem: str
    query_text: str
    topic: Optional[str] = None


class QueryResponse(BaseModel):
    """Client's encrypted answer back to the server"""
    query_id: str
    status: str = "answered"
    encrypted_response: str            # ciphertext for requester
    response_address: str              # BLAKE3 address of the answer blob


class PhraseVaultClient:
    def __init__(self, passphrase: str, server_url: str = "http://localhost:8000"):
        self.vault = vault.Vault(passphrase)           # Your existing encrypted vault
        self.server_url = server_url.rstrip("/")
        self.identity = None                           # Loaded on first use
        self.poll_interval = 5.0                       # seconds between polls

    async def start(self):
        """Background task — run this forever"""
        print(f"🚀 PhraseVault Client started — polling {self.server_url}")
        while True:
            await self._poll_and_evaluate()
            await asyncio.sleep(self.poll_interval)

    async def _poll_and_evaluate(self):
        """Fetch queued queries and evaluate them locally"""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self.server_url}/queries/pending")
                if resp.status_code != 200:
                    return

                queued = resp.json().get("queries", [])
                for q in queued:
                    await self._evaluate_single_query(q)

        except Exception as e:
            print(f"⚠️ Poll error: {e}")

    async def _evaluate_single_query(self, query_data: Dict[str, Any]):
        """Core privacy logic — everything happens locally"""
        q = QueryRequest(**query_data)

        # 1. Verify the requester's credential (JWT for Phase 1)
        try:
            claims: CredentialClaims = CommunityCredential.verify(
                q.credential, q.community_pubkey_pem
            )
        except ValueError as e:
            print(f"❌ Invalid credential for query {q.query_id}: {e}")
            return

        print(f"🔍 Evaluating query {q.query_id} from {claims.community} ({claims.tier})")

        # 2. Load and verify the full forest (or a subtree if you want)
        # For now we assume the forest is already imported via import_forest_to_db
        # In production the client would call self.vault.load_forest()

        # 3. Run local forest search (using your forest.py functions)
        # Example: simple keyword + exact triplet match (expand later with embeddings)
        matching_nodes = self._local_search(q.query_text)

        if not matching_nodes:
            print(f"   No matching data found for query {q.query_id}")
            return

        # 4. Build response (you can make this richer later)
        response_payload = {
            "query_id": q.query_id,
            "matching_nodes": matching_nodes,
            "answered_at": time.time(),
            "owner_did": self.get_did()  # from identity layer
        }

        # 5. Encrypt response for the requester (using their public key from credential)
        # For Phase 1 we use a simple placeholder — replace with real envelope encryption
        encrypted = self.vault.encrypt_response(json.dumps(response_payload))

        # 6. Send encrypted answer back to server
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{self.server_url}/query/{q.query_id}/answer",
                    json={
                        "query_id": q.query_id,
                        "encrypted_response": encrypted,
                        "response_address": "placeholder_address"  # TODO: real BLAKE3
                    }
                )
            print(f"✅ Answered query {q.query_id}")
        except Exception as e:
            print(f"⚠️ Failed to send answer for {q.query_id}: {e}")

    def _local_search(self, query_text: str) -> list:
        """Placeholder for local forest search.
        In Phase 2 this becomes embedding similarity + full forest.py search."""
        # For now: very simple keyword match against loaded forest
        # You can expand this with forest.verify_file or custom search
        return [
            {"node_id": "T4_Timeline_Conjecture", "match_score": 0.92}
        ] if any(word in query_text.lower() for word in ["2046", "timeline", "birth"]) else []

    def get_did(self) -> str:
        """Return did:ethr:0x... from identity layer"""
        if not self.identity:
            # Lazy load from identity.py
            self.identity = self.vault.get_identity()
        return self.identity.did

    def shutdown(self):
        print("🛑 PhraseVault Client shutting down")


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point (add to cli.py later)
# ─────────────────────────────────────────────────────────────────────────────
async def run_client(passphrase: str, server_url: str = "http://localhost:8000"):
    client = PhraseVaultClient(passphrase, server_url)
    try:
        await client.start()
    except asyncio.CancelledError:
        client.shutdown()
    except KeyboardInterrupt:
        client.shutdown()
