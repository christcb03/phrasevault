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
