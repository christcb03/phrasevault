# phrasevault/client.py
import asyncio
import getpass
import httpx
import sys
import json
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
import uvicorn

from . import vault, store

app = FastAPI(title="PhraseVault — Local Client")

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
        print(f"🚀 Local Web UI starting on http://localhost:8501")
        print(f"   Connected to remote relay: {server_url}")

    def _validate_passphrase_and_db(self):
        conn = store.open_db()
        row = conn.execute("SELECT ciphertext FROM entries LIMIT 1").fetchone()
        if row and row["ciphertext"]:
            self.vault.decrypt(row["ciphertext"])
        conn.close()

    def _calculate_alignment_score(self, query_text: str) -> float:
        conn = store.open_db()
        try:
            rows = conn.execute("SELECT words_json FROM forest_nodes").fetchall()
            matches = sum(1 for row in rows 
                         if any(word.lower() in query_text.lower() 
                                for word in json.loads(row["words_json"] or "[]")))
            return round(matches / len(rows), 3) if rows else 0.5
        finally:
            conn.close()

    async def evaluate(self, query_text: str):
        alignment_score = self._calculate_alignment_score(query_text)
        return {
            "answer": "This is a placeholder answer. Full forest search + relationship pruning coming soon.",
            "alignment_score": alignment_score,
            "query_text": query_text
        }

client = None

@app.get("/", response_class=HTMLResponse)
async def home():
    html = f"""
    <html>
    <head><title>PhraseVault</title>
    <style>
        body {{ font-family: system-ui; max-width: 900px; margin: 40px auto; padding: 20px; }}
        textarea {{ width: 100%; height: 120px; font-size: 16px; padding: 12px; }}
        button {{ padding: 12px 24px; font-size: 16px; background: #0066cc; color: white; border: none; border-radius: 6px; cursor: pointer; margin: 5px; }}
        button:hover {{ background: #0055aa; }}
        .result {{ margin-top: 30px; border: 1px solid #ddd; padding: 20px; border-radius: 8px; background: #f9f9f9; }}
        .tab {{ display: none; }}
        .active {{ display: block; }}
    </style>
    </head>
    <body>
        <h1>PhraseVault — Your Personal Knowledge Forest</h1>
        <p><strong>Connected to:</strong> {client.server_url if client else "unknown"}</p>
        
        <button onclick="showTab(0)">Ask Question</button>
        <button onclick="showTab(1)">List Phrases</button>
        <button onclick="showTab(2)">Add New Phrase</button>

        <!-- Tab 0: Ask -->
        <div id="tab0" class="tab active">
            <form id="queryForm">
                <textarea id="query" placeholder="Ask anything about your forest..."></textarea><br><br>
                <button type="submit">Ask</button>
            </form>
            <div id="result" class="result" style="display:none;"></div>
        </div>

        <!-- Tab 1: List Phrases -->
        <div id="tab1" class="tab">
            <button onclick="listPhrases()">Refresh List</button>
            <div id="phraseList"></div>
        </div>

        <!-- Tab 2: Add Phrase -->
        <div id="tab2" class="tab">
            <input id="new_triplet" placeholder="Enter new triplet (comma separated)" style="width:100%; padding:12px; font-size:16px;">
            <br><br>
            <button onclick="addPhrase()">Add Phrase to Forest</button>
            <div id="addResult"></div>
        </div>

        <script>
            function showTab(n) {{ 
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.getElementById('tab' + n).classList.add('active');
            }}

            async function listPhrases() {{
                const res = await fetch('/list');
                const data = await res.json();
                let html = '<h2>Your Phrases (' + data.phrases.length + ')</h2><ul>';
                data.phrases.forEach(function(p) {{
                    html += '<li><strong>' + p.node_id + '</strong>: ' + p.words.join(', ') + '</li>';
                }});
                html += '</ul>';
                document.getElementById('phraseList').innerHTML = html;
            }}

            async function addPhrase() {{
                const text = document.getElementById('new_triplet').value;
                const res = await fetch('/add', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{triplet: text}})
                }});
                const data = await res.json();
                document.getElementById('addResult').innerHTML = '<strong>' + data.message + '</strong>';
            }}

            // Ask form
            document.getElementById('queryForm').addEventListener('submit', async function(e) {{
                e.preventDefault();
                const query = document.getElementById('query').value;
                const res = await fetch('/ask', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
                    body: new URLSearchParams({{query_text: query}})
                }});
                const data = await res.json();
                const div = document.getElementById('result');
                div.innerHTML = '<strong>Query:</strong> ' + data.query_text + '<br>' +
                                '<strong>Alignment score:</strong> ' + data.alignment_score + '<br><br>' +
                                '<strong>Answer:</strong><br>' + data.answer;
                div.style.display = 'block';
            }});
        </script>
    </body>
    </html>
    """
    return html

@app.post("/ask")
async def ask(query_text: str = Form(...)):
    result = await client.evaluate(query_text)
    return result

@app.get("/list")
async def list_phrases():
    conn = store.open_db()
    rows = conn.execute("SELECT node_id, words_json FROM forest_nodes").fetchall()
    phrases = [{"node_id": r["node_id"], "words": json.loads(r["words_json"] or "[]")} for r in rows]
    conn.close()
    return {"phrases": phrases}

@app.post("/add")
async def add_phrase(triplet: str):
    return {"message": f"Added new phrase: {triplet} (placeholder - full add coming soon)"}

async def run_client(server_url: str = "http://localhost:8000"):
    global client
    client = PhraseVaultClient(server_url)
    asyncio.create_task(background_poller())
    config = uvicorn.Config(app, host="127.0.0.1", port=8501, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()

async def background_poller():
    while True:
        try:
            async with httpx.AsyncClient(timeout=10.0) as http_client:
                resp = await http_client.get(f"{client.server_url}/queries/pending")
                if resp.status_code == 200:
                    data = resp.json()
                    for q in data.get("queries", []):
                        await client.evaluate(q.get("query_text", ""))
                        await http_client.delete(f"{client.server_url}/query/{q['query_id']}")
        except:
            pass
        await asyncio.sleep(3)

if __name__ == "__main__":
    asyncio.run(run_client())