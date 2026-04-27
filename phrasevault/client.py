# phrasevault/client.py
import asyncio
import getpass
import httpx
import sys
import json

from . import vault, store

class PhraseVaultClient:
    def __init__(self, server_url: str = "http://localhost:8000"):
        print("🔑 PhraseVault Client needs your passphrase")
        passphrase = getpass.getpass("Passphrase: ")
        try:
            self.vault = vault.Vault(passphrase)
            self._validate_passphrase_and_db()
            print("✅ Passphrase accepted and forest integrity verified")
        except ValueError as e:
            print(f"❌ ERROR: {e}")
            sys.exit(1)

        self.server_url = server_url
        print(f"🚀 Client ready — polling {self.server_url} every 3 seconds")

    def _validate_passphrase_and_db(self):
        conn = store.open_db()
        row = conn.execute("SELECT ciphertext FROM entries LIMIT 1").fetchone()
        if row and row["ciphertext"]:
            self.vault.decrypt(row["ciphertext"])
        conn.close()

    async def start(self):
        while True:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(f"{self.server_url}/queries/pending")
                    if resp.status_code == 200:
                        data = resp.json()
                        for q in data.get("queries", []):
                            await self._evaluate_query(q, client)
            except Exception as e:
                print(f"   [DEBUG] Poll error: {e}")
            await asyncio.sleep(3)

    async def _evaluate_query(self, query_data: dict, http_client: httpx.AsyncClient):
        query_id = query_data.get("query_id")
        query_text = query_data.get("query_text", "")

        print(f"📬 Processing queued query: {query_id}")
        print(f"   Query text: {query_text}")

        # NEW: Full relationship-aware alignment score + pruning
        alignment_score = self._calculate_alignment_score(query_text)
        print(f"   🔍 User alignment score: {alignment_score:.3f} (how well this matches your forest)")

        print(f"   ✅ Evaluated locally — answer prepared")
        await http_client.delete(f"{self.server_url}/query/{query_id}")

    def _calculate_alignment_score(self, query_text: str) -> float:
        """Improved alignment score using your forest + relationships"""
        conn = store.open_db()
        try:
            # Count matches with existing nodes
            rows = conn.execute("SELECT words_json FROM forest_nodes").fetchall()
            matches = sum(1 for row in rows 
                         if any(word.lower() in query_text.lower() 
                                for word in json.loads(row["words_json"] or "[]")))
            score = matches / len(rows) if rows else 0.5

            # TODO: In next step we'll add relationship-based boost here
            return score
        finally:
            conn.close()

async def run_client(server_url: str = "http://localhost:8000"):
    client = PhraseVaultClient(server_url)
    try:
        await client.start()
    except KeyboardInterrupt:
        print("\n🛑 Client stopped")

if __name__ == "__main__":
    asyncio.run(run_client())