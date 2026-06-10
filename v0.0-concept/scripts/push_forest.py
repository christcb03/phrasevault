#!/usr/bin/env python3
"""
Push a local forest JSON file to a PhraseVault server.

Usage:
    python scripts/push_forest.py \
        --forest truth_forest_v4.json \
        --server https://phrasevault.turnernetworking.com \
        --api-key <your-api-key>

    # Strip personal branches before sending:
    python scripts/push_forest.py ... --no-personal
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Push a forest JSON to a PhraseVault server")
    parser.add_argument("--forest",   required=True, help="Path to forest JSON file")
    parser.add_argument("--server",   required=True, help="Server base URL")
    parser.add_argument("--api-key",  required=True, help="X-API-Key value")
    parser.add_argument("--no-personal", action="store_true",
                        help="Strip personal_axiom_branches before sending")
    args = parser.parse_args()

    forest_path = Path(args.forest)
    if not forest_path.exists():
        print(f"ERROR: {forest_path} not found", file=sys.stderr)
        sys.exit(1)

    data = json.loads(forest_path.read_text())

    if args.no_personal:
        removed = list(k for k in data.get("personal_axiom_branches", {}) if k != "note")
        data.pop("personal_axiom_branches", None)
        if removed:
            print(f"Stripped personal branches: {removed}")

    payload = json.dumps({"forest_json": json.dumps(data)}).encode("utf-8")

    url = args.server.rstrip("/") + "/forest/import"
    print(f"Pushing {forest_path.name} ({len(data.get('trees', []))} trees) → {url}")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": args.api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            print(f"✓  inserted={result.get('inserted')}  updated={result.get('updated')}  "
                  f"errors={result.get('errors')}")
            print(f"   fingerprint: {result.get('fingerprint')}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"ERROR {e.code}: {body}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
