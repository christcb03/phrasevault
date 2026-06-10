#!/usr/bin/env python3
"""
phrasevault/cli.py
Main command-line interface for PhraseVault
"""

import argparse
import sys
import asyncio
import getpass   # ← Added this line

def main():
    parser = argparse.ArgumentParser(
        description="PhraseVault — Passphrase-first encrypted knowledge network"
    )
    parser.add_argument(
        "--passphrase",
        "-p",
        help="Passphrase (will be prompted if not provided)",
        default=None,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ====================== IDENTITY ======================
    identity_parser = subparsers.add_parser("identity", help="Manage your secp256k1 identity / DID")
    identity_sub = identity_parser.add_subparsers(dest="identity_cmd", required=True)
    identity_sub.add_parser("keygen", help="Generate or re-derive your identity")
    identity_sub.add_parser("whoami", help="Show your DID and public key")

    # ====================== SERVER / CLIENT ======================
    server_parser = subparsers.add_parser("server", help="Start the dumb relay server")
    client_parser = subparsers.add_parser("client", help="Start the intelligent client")
    client_parser.add_argument("--server", default="http://localhost:8000", help="Server URL")

    # ====================== IMPORT / EXPORT ======================
    import_parser = subparsers.add_parser("import", help="Import forest from JSON")
    import_parser.add_argument("json_file", help="Path to truth_forest_*.json")

    export_parser = subparsers.add_parser("export", help="Export forest to JSON")
    export_parser.add_argument("json_file", nargs="?", default="exported_forest.json")

    # ====================== RE-ENCRYPT (ONE-TIME MIGRATION) ======================
    reencrypt_parser = subparsers.add_parser("reencrypt", help="One-time migration: encrypt all existing data with your passphrase")

    # ====================== OTHER COMMANDS ======================
    store_parser = subparsers.add_parser("store", help="Store a triplet")
    get_parser = subparsers.add_parser("get", help="Retrieve a triplet")
    list_parser = subparsers.add_parser("list", help="List all nodes")
    score_parser = subparsers.add_parser("score", help="Show forest fingerprint")

    args = parser.parse_args()

    if args.command == "identity":
        from .identity import main as identity_main
        identity_main(args)

    elif args.command == "server":
        import uvicorn
        from .server import app
        print(f"🚀 Starting PhraseVault server on 0.0.0.0:8000")
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="critical", access_log=False, log_config=None)

    elif args.command == "client":
        from .client import run_client
        asyncio.run(run_client(args.server))

    elif args.command == "import":
        from .forest import import_forest_to_db
        result = import_forest_to_db(args.json_file)
        print(result)

    elif args.command == "reencrypt":
        from .forest import re_encrypt_existing_data
        passphrase = args.passphrase or getpass.getpass("Passphrase for re-encryption: ")
        result = re_encrypt_existing_data(passphrase)
        print(result)

    else:
        print(f"Command '{args.command}' not fully implemented yet.")

    return 0


if __name__ == "__main__":
    sys.exit(main())