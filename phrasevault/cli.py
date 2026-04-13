"""
phrasevault/cli.py
──────────────────
Minimal command-line interface for local testing.
Run from the HomeLab directory:

  python -m phrasevault.cli store  "sky is blue" "is" "true" --confidence 0.12
  python -m phrasevault.cli get    <address_hex>
  python -m phrasevault.cli list
  python -m phrasevault.cli export out.pvx
  python -m phrasevault.cli import out.pvx --from another_vault.db
  python -m phrasevault.cli score  0.88

Passphrase is read from PHRASEVAULT_PASS environment variable or prompted.
Never passed as a CLI argument (would appear in shell history).
"""

import os
import sys
import json
import getpass
import argparse
from pathlib import Path

# Allow running as `python -m phrasevault.cli` from the HomeLab directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from phrasevault import crypto, store, transfer, identity as id_module
from phrasevault.vault import Vault


def get_passphrase() -> str:
    p = os.environ.get("PHRASEVAULT_PASS")
    if p:
        return p
    return getpass.getpass("PhraseVault passphrase: ")


def get_db_path(args) -> Path:
    return Path(getattr(args, "db", None) or store.DEFAULT_DB)


# ── commands ──────────────────────────────────────────────────────────────────

def cmd_store(args):
    passphrase = get_passphrase()
    with Vault(passphrase, get_db_path(args)) as v:
        print(f"[store] Deriving key... (Argon2id ~1s)")
        addr = v.store_triplet(
            subject    = args.subject,
            predicate  = args.predicate,
            object_    = args.object,
            confidence = args.confidence,
            shell      = args.shell,
            node_id    = args.node_id or "",
            node_type  = args.node_type or "",
        )
        print(f"[store] ✓ Stored at address: {addr}")
        print(f"[store] ✓ Total entries: {v.entry_count()}")


def cmd_get(args):
    passphrase = get_passphrase()
    with Vault(passphrase, get_db_path(args)) as v:
        print(f"[get] Deriving key... (Argon2id ~1s)")
        try:
            triplet = v.retrieve_triplet(args.address)
            print(json.dumps(triplet, indent=2))
        except KeyError:
            print(f"[get] ✗ No entry found at {args.address}")
            sys.exit(1)
        except Exception as e:
            print(f"[get] ✗ Decryption failed: {e}")
            print("[get]   (Wrong passphrase or tampered data)")
            sys.exit(1)


def cmd_list(args):
    passphrase = get_passphrase()
    with Vault(passphrase, get_db_path(args)) as v:
        entries = v.list_entries(include_superseded=args.all)
        if not entries:
            print("[list] No entries in vault.")
            return
        print(f"{'ADDRESS[:16]':<18} {'POS':>4} {'CONF':>6} {'SHELL':>5} {'SUP':>4}")
        print("─" * 50)
        for e in entries:
            sup = "✓" if e["superseded"] else ""
            print(
                f"{e['address'][:16]}…  "
                f"{e['chain_position']:>4}  "
                f"{e['confidence']:>6.3f}  "
                f"{e['shell']:>5}  "
                f"{sup:>4}"
            )
        print(f"─" * 50)
        print(f"Total: {len(entries)} entries")


def cmd_export(args):
    passphrase = get_passphrase()
    db_path    = get_db_path(args)
    out_path   = Path(args.output)
    conn = store.open_db(db_path)
    store.init_schema(conn)
    if args.since is not None:
        n = transfer.export_since(conn, args.since, out_path)
    else:
        n = transfer.export_all(conn, out_path)
    conn.close()
    print(f"[export] ✓ Wrote {n} entries to {out_path}")


def cmd_import(args):
    in_path  = Path(args.input)
    db_path  = get_db_path(args)
    conn     = store.open_db(db_path)
    store.init_schema(conn)
    imported, skipped = transfer.import_file(
        conn, in_path, origin_instance=args.origin or "file"
    )
    conn.close()
    print(f"[import] ✓ Imported: {imported}  Skipped/failed: {skipped}")


def cmd_score(args):
    """Show all confidence score utilities for a given value (no DB needed)."""
    c = args.confidence
    print(f"  confidence:            {c}")
    print(f"  impossibility_measure: {crypto.impossibility_measure(c):.15f}")
    print(f"  probability_true:      {(1-c)*100:.1f}%")
    print(f"  bits_of_surprise:      {crypto.impossibility_measure(c) / 0.6931:.4f} bits")
    if args.anchors:
        anchors = [float(x) for x in args.anchors.split(",")]
        eff = crypto.effective_score(c, anchors)
        print(f"  effective_score:       {eff:.10f}  (anchors: {anchors})")


def cmd_sync_info(args):
    """Print sync summary for sharing with a peer."""
    db_path = get_db_path(args)
    conn    = store.open_db(db_path)
    store.init_schema(conn)
    info    = transfer.sync_summary(conn)
    conn.close()
    print(json.dumps(info, indent=2))


# ── identity commands ─────────────────────────────────────────────────────────

def cmd_identity_keygen(args):
    """
    Derive and cache the secp256k1 keypair for this passphrase.
    Safe to run multiple times (idempotent).
    Takes ~2s (two Argon2id operations).
    """
    passphrase = get_passphrase()
    print("[identity] Deriving identity keypair... (Argon2id ~2s)")
    with Vault(passphrase, get_db_path(args)) as v:
        info = v.create_identity()
    print(f"[identity] ✓ Identity created")
    print(f"[identity]   DID:         {info['did']}")
    print(f"[identity]   ETH address: {info['eth_address']}")
    print(f"[identity]   Public key:  {info['public_key_hex']}")
    print()
    print("[identity] Your DID is your permanent identity on the PhraseVault network.")
    print("[identity] It is derived from your passphrase — same passphrase = same DID.")


def cmd_identity_whoami(args):
    """Show the DID and public key for the current passphrase (fast, no Argon2id)."""
    passphrase = get_passphrase()
    with Vault(passphrase, get_db_path(args)) as v:
        info = v.get_identity()
    if info is None:
        print("[identity] No identity found. Run `phrasevault identity keygen` first.")
        sys.exit(1)
    print(f"DID:         {info['did']}")
    print(f"ETH address: {info['eth_address']}")
    print(f"Public key:  {info['public_key_hex']}")


def cmd_identity_pubkey(args):
    """Print only the public key hex (useful for piping to other commands)."""
    passphrase = get_passphrase()
    with Vault(passphrase, get_db_path(args)) as v:
        info = v.get_identity()
    if info is None:
        print("[identity] No identity found. Run `phrasevault identity keygen` first.",
              file=sys.stderr)
        sys.exit(1)
    print(info["public_key_hex"])


def cmd_identity_sign(args):
    """
    Sign a message with this vault's secp256k1 private key.
    Outputs the 65-byte signature as hex.  Takes ~1s.
    """
    passphrase = get_passphrase()
    message = args.message.encode("utf-8")
    print("[identity] Signing... (Argon2id ~1s)")
    with Vault(passphrase, get_db_path(args)) as v:
        try:
            sig = v.sign_message(message)
        except ValueError as e:
            print(f"[identity] ✗ {e}")
            sys.exit(1)
    print(f"[identity] ✓ Signature: {sig.hex()}")


def cmd_identity_verify(args):
    """
    Verify a signature against a message and a known public key.
    All three are required.  No passphrase needed — verification is public.
    """
    message    = args.message.encode("utf-8")
    pubkey_hex = args.pubkey
    try:
        sig_bytes = bytes.fromhex(args.signature)
    except ValueError:
        print("[identity] ✗ Signature must be hex-encoded.")
        sys.exit(1)
    compressed_pubkey = bytes.fromhex(pubkey_hex)
    valid = id_module.verify(compressed_pubkey, message, sig_bytes)
    if valid:
        eth_addr = id_module.pubkey_to_eth_address(compressed_pubkey)
        print(f"[identity] ✓ Valid signature from {eth_addr}")
    else:
        print("[identity] ✗ Invalid signature.")
        sys.exit(1)


def cmd_identity(args):
    """Dispatch to identity sub-subcommands."""
    {
        "keygen":  cmd_identity_keygen,
        "whoami":  cmd_identity_whoami,
        "pubkey":  cmd_identity_pubkey,
        "sign":    cmd_identity_sign,
        "verify":  cmd_identity_verify,
    }[args.identity_command](args)

# In cli.py — add to the main parser
identity_parser = subparsers.add_parser("identity", help="Manage secp256k1 identity")
# ... existing identity commands ...

# New server/client commands
server_parser = subparsers.add_parser("server", help="Start dumb relay server")
server_parser.add_argument("--host", default="0.0.0.0")
server_parser.add_argument("--port", type=int, default=8000)

client_parser = subparsers.add_parser("client", help="Run client query evaluator")

# ── entry point ───────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(prog="phrasevault", description="PhraseVault local CLI")
    p.add_argument("--db", default=None, help="Path to SQLite database (default: phrasevault.db)")
    sub = p.add_subparsers(dest="command", required=True)

    # store
    s = sub.add_parser("store", help="Encrypt and store a triplet")
    s.add_argument("subject");   s.add_argument("predicate");   s.add_argument("object")
    s.add_argument("--confidence", type=float, default=0.5)
    s.add_argument("--shell", type=int, default=3)
    s.add_argument("--node-id", dest="node_id", default="")
    s.add_argument("--node-type", dest="node_type", default="")

    # get
    g = sub.add_parser("get", help="Decrypt and retrieve a triplet by address")
    g.add_argument("address")

    # list
    l = sub.add_parser("list", help="List all entries (metadata only, no decryption)")
    l.add_argument("--all", action="store_true", help="Include superseded entries")

    # export
    e = sub.add_parser("export", help="Export entries to a .pvx transfer file")
    e.add_argument("output", help="Output file path (e.g. export.pvx)")
    e.add_argument("--since", type=int, default=None, help="Only export entries after this chain position")

    # import
    i = sub.add_parser("import", help="Import entries from a .pvx transfer file")
    i.add_argument("input", help="Input .pvx file path")
    i.add_argument("--origin", default="file", help="Label for the origin instance")

    # score
    sc = sub.add_parser("score", help="Show confidence score utilities (no DB)")
    sc.add_argument("confidence", type=float)
    sc.add_argument("--anchors", default=None, help="Comma-separated anchor scores, e.g. 0.08,0.11")

    # sync-info
    si = sub.add_parser("sync-info", help="Show sync state for sharing with a peer")

    # identity
    id_p = sub.add_parser("identity", help="Manage secp256k1 identity keypair")
    id_sub = id_p.add_subparsers(dest="identity_command", required=True)

    id_sub.add_parser("keygen",
        help="Derive and cache your secp256k1 keypair from your passphrase (~2s)")

    id_sub.add_parser("whoami",
        help="Show your DID, Ethereum address, and public key")

    id_sub.add_parser("pubkey",
        help="Print only your public key hex (for piping)")

    id_sign = id_sub.add_parser("sign", help="Sign a message with your private key (~1s)")
    id_sign.add_argument("message", help="Message to sign (UTF-8 string)")

    id_verify = id_sub.add_parser("verify", help="Verify a signature (no passphrase needed)")
    id_verify.add_argument("message",   help="Original message (UTF-8 string)")
    id_verify.add_argument("signature", help="Signature as hex string")
    id_verify.add_argument("pubkey",    help="Signer's public key as hex string")

    args = p.parse_args()
    {
        "store":     cmd_store,
        "get":       cmd_get,
        "list":      cmd_list,
        "export":    cmd_export,
        "import":    cmd_import,
        "score":     cmd_score,
        "sync-info": cmd_sync_info,
        "identity":  cmd_identity,
    }[args.command](args)


if __name__ == "__main__":
    main()
