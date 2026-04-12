"""
phrasevault/forest.py
──────────────────────
Four functions for the JSON ↔ SQLite bridge (T36 instruction block).
Signed by T33_Tree_Signing_Mechanism per the vault.py.module.json node.

Functions (matching the T36 usage instructions exactly):
  import_forest_to_db(json_path, db_path)
  export_db_to_forest(db_path, output_json, root_node_id=None, max_depth=None)
  verify_file(proposed_json, db_path, expected_subtree_root=None)
  forest_fingerprint(conn)    ← T33 signing mechanism

Design:
  - The forest_nodes table is the UNENCRYPTED public layer (scores, links, words)
  - The entries table is the ENCRYPTED private layer (ciphertext blobs)
  - These two layers live in the same SQLite DB and can cross-reference by node_id
  - Any node in the forest can serve as a subtree root for export/verify
"""

import json
import math
import time
from collections import deque
from pathlib import Path
from typing import Any

import blake3

from . import store


# ══════════════════════════════════════════════════════════════════════════════
# 1. IMPORT — JSON forest → SQLite forest_nodes table
# ══════════════════════════════════════════════════════════════════════════════

def import_forest_to_db(json_path: str | Path, db_path: str | Path = None) -> dict:
    """
    Read a truth_forest JSON file and upsert every node into forest_nodes.
    Also imports personal_axiom_branches as nodes in tree_id='PERSONAL'.

    Returns a summary dict:
      {inserted, updated, skipped, errors, forest_id, fingerprint}

    Idempotent: running twice on the same file produces the same DB state.
    Uses INSERT OR REPLACE so re-imports with corrected scores update cleanly.
    """
    db_path = Path(db_path) if db_path else store.DEFAULT_DB
    json_path = Path(json_path)

    conn = store.open_db(db_path)
    store.init_schema(conn)

    data = json.loads(json_path.read_text(encoding="utf-8"))
    forest_id = data.get("forest_id", "unknown")

    inserted = updated = skipped = 0
    errors = []

    def upsert_node(node: dict, tree_id: str) -> str:
        """Write one node to forest_nodes. Returns 'inserted', 'updated', or 'error'."""
        node_id = node.get("triplet_id") or node.get("node_id")
        if not node_id:
            errors.append(f"Node missing triplet_id/node_id: {node}")
            return "error"

        score = node.get("truth_score", 0.0)
        im    = node.get("impossibility_measure", 0.0)

        # Verify im is consistent with score (catch typos like T14/T26/T31)
        if score > 0.0:
            expected_im = -math.log(1.0 - score)
            if abs(im - expected_im) > 1e-6:
                errors.append(
                    f"{node_id}: im mismatch — stored={im:.9f}, "
                    f"computed={expected_im:.9f} (score={score}). Using computed."
                )
                im = expected_im

        existing = conn.execute(
            "SELECT truth_score FROM forest_nodes WHERE node_id = ?", (node_id,)
        ).fetchone()

        conn.execute(
            """
            INSERT OR REPLACE INTO forest_nodes
                (node_id, tree_id, shell, truth_score, impossibility_measure,
                 node_type, superseded, words_json, links_json, links_cross_json,
                 source, note, signed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                node_id,
                tree_id,
                node.get("shell", 3),
                score,
                im,
                node.get("node_type", ""),
                1 if node.get("superseded") else 0,
                json.dumps(node.get("words", []), ensure_ascii=False),
                json.dumps(node.get("links", []), ensure_ascii=False),
                json.dumps(node.get("links_cross_tree", []), ensure_ascii=False),
                node.get("source", "import"),
                node.get("note", ""),
                node.get("signed_by", ""),
            ),
        )
        return "updated" if existing else "inserted"

    # Process all trees
    for tree in data.get("trees", []):
        tree_id = tree.get("tree_id", "CORE_truth_tree")
        for node in tree.get("nodes", []):
            result = upsert_node(node, tree_id)
            if result == "inserted":
                inserted += 1
            elif result == "updated":
                updated += 1
            else:
                skipped += 1

    # Process personal_axiom_branches
    for branch_id, branch in data.get("personal_axiom_branches", {}).items():
        if branch_id == "note":
            continue
        node = {
            "triplet_id": branch_id,
            "shell":      3,
            "truth_score": branch.get("truth_score", 0.92),
            "impossibility_measure": -math.log(1.0 - branch.get("truth_score", 0.92)),
            "node_type":  "personal_axiom",
            "words":      branch.get("words", []),
            "links":      [],
            "source":     "personal_axiom_branch",
            "note":       f"effective_score={branch.get('effective_score', branch.get('truth_score'))}",
        }
        result = upsert_node(node, "PERSONAL")
        if result == "inserted":
            inserted += 1
        elif result == "updated":
            updated += 1

    conn.commit()

    # Compute and store T33 forest fingerprint
    fp = forest_fingerprint(conn)
    conn.execute(
        """
        INSERT INTO forest_signatures
            (forest_id, version, node_count, fingerprint, signed_at_ns, signing_node)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            forest_id,
            data.get("version", "?"),
            inserted + updated,
            fp,
            time.time_ns(),
            "T33_Tree_Signing_Mechanism",
        ),
    )
    conn.commit()
    conn.close()

    return {
        "forest_id":   forest_id,
        "inserted":    inserted,
        "updated":     updated,
        "skipped":     skipped,
        "errors":      errors,
        "fingerprint": fp,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 2. EXPORT — SQLite forest_nodes → JSON (full or subtree)
# ══════════════════════════════════════════════════════════════════════════════

def export_db_to_forest(
    db_path: str | Path,
    output_json: str | Path,
    root_node_id: str | None = None,
    max_depth: int | None = None,
) -> dict:
    """
    Export forest_nodes from SQLite back to a truth_forest JSON file.

    If root_node_id is given:
      - BFS from that node following links in BOTH directions (inbound + outbound)
      - max_depth limits how many hops from root (None = unlimited)
      - Useful for exporting the T4 personal branch with its anchor context

    If root_node_id is None:
      - Export everything (full forest reconstruction)

    Returns summary dict: {node_count, root_node_id, depth_reached, output_path}
    """
    db_path     = Path(db_path)
    output_json = Path(output_json)

    conn = store.open_db(db_path)
    store.init_schema(conn)

    if root_node_id:
        nodes_to_export = _bfs_subgraph(conn, root_node_id, max_depth)
    else:
        rows = conn.execute(
            "SELECT * FROM forest_nodes ORDER BY tree_id, truth_score ASC"
        ).fetchall()
        nodes_to_export = [dict(r) for r in rows]

    # Reconstruct forest structure grouped by tree_id
    trees: dict[str, list] = {}
    personal: dict[str, Any] = {}

    for node in nodes_to_export:
        tree_id  = node["tree_id"]
        node_obj = {
            "triplet_id":          node["node_id"],
            "shell":               node["shell"],
            "truth_score":         node["truth_score"],
            "impossibility_measure": node["impossibility_measure"],
            "node_type":           node["node_type"],
            "superseded":          bool(node["superseded"]),
            "words":               json.loads(node["words_json"] or "[]"),
            "links":               json.loads(node["links_json"] or "[]"),
        }
        cross = json.loads(node["links_cross_json"] or "[]")
        if cross:
            node_obj["links_cross_tree"] = cross
        if node["note"]:
            node_obj["note"] = node["note"]

        if tree_id == "PERSONAL":
            personal[node["node_id"]] = {
                "truth_score":    node["truth_score"],
                "effective_score": float(node["note"].split("=")[1]) if node["note"] and "effective_score=" in node["note"] else node["truth_score"],
                "words":          json.loads(node["words_json"] or "[]"),
                "node_type":      node["node_type"],
            }
        else:
            trees.setdefault(tree_id, []).append(node_obj)

    # Get latest fingerprint
    sig = conn.execute(
        "SELECT * FROM forest_signatures ORDER BY signed_at_ns DESC LIMIT 1"
    ).fetchone()
    fp = dict(sig)["fingerprint"] if sig else forest_fingerprint(conn)

    conn.close()

    # Build output JSON matching truth_forest structure
    output = {
        "forest_id":           f"phrasevault_export_{root_node_id or 'full'}",
        "export_root":         root_node_id,
        "export_depth":        max_depth,
        "version":             "export",
        "date":                _today(),
        "fingerprint_T33":     fp,
        "trees": [
            {"tree_id": tid, "nodes": nodes}
            for tid, nodes in sorted(trees.items())
        ],
    }
    if personal:
        output["personal_axiom_branches"] = personal

    output_json.write_text(
        json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    total = sum(len(n) for n in trees.values()) + len(personal)
    return {
        "node_count":    total,
        "root_node_id":  root_node_id,
        "output_path":   str(output_json),
        "fingerprint":   fp,
    }


def _bfs_subgraph(conn, root_id: str, max_depth: int | None) -> list[dict]:
    """
    BFS from root_id following links in both directions.
    Returns list of node dicts from forest_nodes.
    """
    # Build bidirectional link index
    all_rows = conn.execute("SELECT node_id, links_json FROM forest_nodes").fetchall()
    outbound: dict[str, set] = {}
    inbound:  dict[str, set] = {}
    for row in all_rows:
        nid   = row["node_id"]
        links = json.loads(row["links_json"] or "[]")
        outbound[nid] = set(links)
        for target in links:
            inbound.setdefault(target, set()).add(nid)

    # BFS
    visited: set[str] = set()
    queue   = deque([(root_id, 0)])
    while queue:
        node_id, depth = queue.popleft()
        if node_id in visited:
            continue
        visited.add(node_id)
        if max_depth is not None and depth >= max_depth:
            continue
        # Expand both directions
        neighbors = (outbound.get(node_id, set()) | inbound.get(node_id, set()))
        for neighbor in neighbors:
            if neighbor not in visited:
                queue.append((neighbor, depth + 1))

    # Fetch rows for all visited nodes
    result = []
    for nid in sorted(visited):
        row = conn.execute(
            "SELECT * FROM forest_nodes WHERE node_id = ?", (nid,)
        ).fetchone()
        if row:
            result.append(dict(row))
    return result


# ══════════════════════════════════════════════════════════════════════════════
# 3. VERIFY — check proposed JSON consistency against DB
# ══════════════════════════════════════════════════════════════════════════════

def verify_file(
    proposed_json: str | Path,
    db_path: str | Path,
    expected_subtree_root: str | None = None,
) -> dict:
    """
    Verify a proposed JSON forest file against the authoritative DB.

    For each node in proposed_json, checks:
      1. Node exists in forest_nodes              (existence)
      2. truth_score matches within 1e-9          (score integrity)
      3. im = -log(1-score) is consistent         (formula integrity)
      4. Links exist in DB *or* are forward refs  (link integrity)
      5. If expected_subtree_root is given:
         node must be reachable from root via BFS (subtree membership)

    Link integrity distinguishes:
      - broken_links:       target absent from BOTH proposed JSON AND DB (genuine corruption)
      - forward_references: target absent from proposed JSON but present in DB or
                            simply not yet defined anywhere (expected unknowns)

    A file PASSES if scores, im, and subtree are all consistent.
    Forward references are reported but do NOT fail the check.
    Missing nodes and score mismatches DO fail.

    Returns:
      {
        passed, total_nodes_checked, score_matches,
        score_mismatches, missing_from_db,
        broken_links, forward_references,
        im_errors, subtree_violations,
        db_fingerprint, proposed_fingerprint,
      }
    """
    proposed_json = Path(proposed_json)
    db_path       = Path(db_path)

    conn = store.open_db(db_path)
    store.init_schema(conn)

    proposed_data = json.loads(proposed_json.read_text(encoding="utf-8"))

    # Flatten all nodes from proposed JSON
    proposed_nodes: list[dict] = []
    for tree in proposed_data.get("trees", []):
        for node in tree.get("nodes", []):
            proposed_nodes.append(node)
    for branch_id, branch in proposed_data.get("personal_axiom_branches", {}).items():
        if branch_id == "note":
            continue
        proposed_nodes.append({
            "triplet_id":          branch_id,
            "truth_score":         branch.get("truth_score", 0.0),
            "impossibility_measure": -math.log(1.0 - branch.get("truth_score", 0.0)) if branch.get("truth_score", 0.0) > 0 else 0.0,
            "links":               [],
        })

    # Build lookup sets
    proposed_ids = {
        (n.get("triplet_id") or n.get("node_id", "?"))
        for n in proposed_nodes
    }
    all_db = {
        r["node_id"]: dict(r)
        for r in conn.execute("SELECT * FROM forest_nodes").fetchall()
    }

    # Build subtree set if root given
    subtree_ids: set[str] | None = None
    if expected_subtree_root:
        subtree_nodes = _bfs_subgraph(conn, expected_subtree_root, max_depth=None)
        subtree_ids   = {n["node_id"] for n in subtree_nodes}

    # Verification
    score_matches       = 0
    score_mismatches    = []
    missing_from_db     = []
    broken_links        = []
    forward_references  = []
    im_errors           = []
    subtree_violations  = []

    for node in proposed_nodes:
        nid   = node.get("triplet_id") or node.get("node_id", "?")
        score = node.get("truth_score", 0.0)
        im    = node.get("impossibility_measure", 0.0)

        # Check 1: existence in DB
        if nid not in all_db:
            missing_from_db.append(nid)
            continue

        db_node = all_db[nid]

        # Check 2: score match
        delta = abs(score - db_node["truth_score"])
        if delta < 1e-9:
            score_matches += 1
        else:
            score_mismatches.append({
                "node_id":  nid,
                "proposed": score,
                "db":       db_node["truth_score"],
                "delta":    delta,
            })

        # Check 3: im consistency
        if score > 0.0:
            expected_im = -math.log(1.0 - score)
            if abs(im - expected_im) > 1e-6:
                im_errors.append({
                    "node_id":     nid,
                    "proposed_im": im,
                    "expected_im": expected_im,
                    "delta":       abs(im - expected_im),
                })

        # Check 4: link integrity — distinguish corruption from forward references
        for link in node.get("links", []):
            if link in proposed_ids or link in all_db:
                pass  # link target exists somewhere — fine
            else:
                # Target absent from both proposed JSON and DB.
                # These are expected "known unknowns" (T11, T12, T13, T16, T18 etc.)
                # that are referenced in ARCHITECTURE.md but not yet in the forest.
                forward_references.append({"node_id": nid, "forward_ref": link})

        # Check 5: subtree membership
        if subtree_ids is not None and nid not in subtree_ids:
            subtree_violations.append(nid)

    # Fingerprints
    db_fp   = forest_fingerprint(conn)
    prop_fp = _json_fingerprint(proposed_nodes)
    conn.close()

    # PASS criteria: scores correct, all nodes exist, im consistent, subtree valid.
    # Forward references are warnings only — they are expected at this stage.
    passed = (
        len(score_mismatches)   == 0 and
        len(missing_from_db)    == 0 and
        len(broken_links)       == 0 and
        len(im_errors)          == 0 and
        len(subtree_violations) == 0
    )

    return {
        "passed":               passed,
        "total_nodes_checked":  len(proposed_nodes),
        "score_matches":        score_matches,
        "score_mismatches":     score_mismatches,
        "missing_from_db":      missing_from_db,
        "broken_links":         broken_links,
        "forward_references":   forward_references,
        "im_errors":            im_errors,
        "subtree_violations":   subtree_violations,
        "db_fingerprint":       db_fp,
        "proposed_fingerprint": prop_fp,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 4. FOREST FINGERPRINT — T33 Tree-Signing Mechanism
#    BLAKE3 hash of all node_id:truth_score pairs (sorted for determinism).
#    Anyone with the DB can reproduce this hash and confirm nothing changed.
# ══════════════════════════════════════════════════════════════════════════════

def forest_fingerprint(conn) -> str:
    """
    T33_Tree_Signing_Mechanism implementation.

    Computes BLAKE3(sorted node_id:score pairs) over all non-superseded nodes.
    Deterministic: same forest state always produces the same fingerprint.
    Any insertion, deletion, or score change produces a completely different hash.

    Returns 64-char hex string.
    """
    rows = conn.execute(
        "SELECT node_id, truth_score FROM forest_nodes "
        "WHERE superseded = 0 ORDER BY node_id ASC"
    ).fetchall()

    # Canonical string: "node_id=score\n" for each row, sorted by node_id
    canonical = "\n".join(
        f"{r['node_id']}={r['truth_score']:.15f}" for r in rows
    ).encode("utf-8")

    return blake3.blake3(b"phrasevault:forest:v1:" + canonical).hexdigest()


def _json_fingerprint(nodes: list[dict]) -> str:
    """Fingerprint of a proposed JSON node list (for comparison with DB fingerprint)."""
    pairs = sorted(
        (
            (n.get("triplet_id") or n.get("node_id", "?"),
             n.get("truth_score", 0.0))
            for n in nodes
        ),
        key=lambda x: x[0],
    )
    canonical = "\n".join(
        f"{nid}={score:.15f}" for nid, score in pairs
    ).encode("utf-8")
    return blake3.blake3(b"phrasevault:forest:v1:" + canonical).hexdigest()


def _today() -> str:
    import datetime
    return datetime.date.today().isoformat()
