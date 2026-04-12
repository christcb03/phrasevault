# PhraseVault

A distributed encrypted knowledge network where a passphrase is simultaneously
the storage address, the encryption key, and the namespace for your data.

No accounts. No servers. No cloud dependency. Your passphrase is the only secret.

## Core idea

```
passphrase → BLAKE3   → storage address  (fast, for lookup)
passphrase → Argon2id → encryption key   (slow, memory-hard, for security)
```

Data is stored as RDF-style triplets `(subject, predicate, object)` in a local
SQLite database. Entries are chain-linked — inserting or reordering entries
breaks every subsequent address. Transfer between instances uses `.pvx` bundles
with integrity verification.

The confidence scoring system rates certainty. Lower score = more certain.
`0.0` = tautology. Approaching `1.0` = practically impossible.
`impossibility_measure = -log(1 - confidence)`.

## Cryptographic primitives

- **BLAKE3** — address derivation, chain linking, forest fingerprinting
- **Argon2id** — memory-hard key derivation (64 MB, 3 iterations)
- **XSalsa20-Poly1305** — authenticated encryption via PyNaCl SecretBox

All algorithms are public. Security comes entirely from your passphrase.
See [SECURITY.md](SECURITY.md) for the full threat model.

## Install

```bash
pip install -r requirements.txt
pip install -e .
```

## Quick start

```python
from phrasevault.vault import Vault

vault = Vault("my_knowledge.db")

vault.store_triplet(
    passphrase="correct horse battery staple",
    subject="water",
    predicate="boils_at",
    object="100C at sea level"
)

result = vault.retrieve_triplet(
    passphrase="correct horse battery staple",
    chain_position=0
)
print(result)
```

## CLI

```bash
export PHRASEVAULT_PASS="your passphrase here"
phrasevault store --subject water --predicate boils_at --object "100C"
phrasevault get --position 0
phrasevault export --out transfer.pvx
phrasevault import --file transfer.pvx
```

The passphrase is read from `PHRASEVAULT_PASS` or prompted securely —
never passed as a CLI argument.

## Forest (knowledge graph)

```python
from phrasevault.forest import import_forest_to_db, verify_file

result = import_forest_to_db("examples/example_forest.json", "knowledge.db")
print(result["fingerprint"])  # deterministic 64-char BLAKE3 hex

report = verify_file("proposed.json", "knowledge.db")
print(report["passed"])
```

## Project structure

```
phrasevault/
  crypto.py    — pure crypto primitives, zero I/O
  store.py     — SQLite schema and raw DB operations
  vault.py     — store_triplet / retrieve_triplet pipeline
  transfer.py  — .pvx export/import/verify
  forest.py    — import/export/verify/fingerprint
  cli.py       — command-line interface
examples/
  example_forest.json
tests/
SECURITY.md
```

## License

GNU General Public License v3 or later. See [LICENSE](LICENSE).
