"""Tests for phrasevault.forest — import, export, verify, fingerprint."""
import json
import pytest
from pathlib import Path
from phrasevault.forest import (
    import_forest_to_db, export_db_to_forest, verify_file, forest_fingerprint,
)
from phrasevault.store import open_db

EXAMPLE = Path(__file__).parent.parent / "examples" / "example_forest.json"


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "forest.db")

@pytest.fixture
def out(tmp_path):
    return str(tmp_path / "export.json")


def test_import_example(db):
    r = import_forest_to_db(str(EXAMPLE), db)
    assert r["errors"] == []
    assert r["inserted"] > 0
    assert len(r["fingerprint"]) == 64

def test_import_idempotent(db):
    r1 = import_forest_to_db(str(EXAMPLE), db)
    r2 = import_forest_to_db(str(EXAMPLE), db)
    assert r1["fingerprint"] == r2["fingerprint"]

def test_export_creates_file(db, out):
    import_forest_to_db(str(EXAMPLE), db)
    r = export_db_to_forest(db, out)
    assert r["node_count"] > 0
    assert Path(out).exists()

def test_verify_passes_on_clean_import(db):
    import_forest_to_db(str(EXAMPLE), db)
    report = verify_file(str(EXAMPLE), db)
    assert report["passed"] is True
    assert report["score_mismatches"] == []
    assert report["im_errors"] == []

def test_fingerprint_deterministic(db):
    import_forest_to_db(str(EXAMPLE), db)
    conn = open_db(db)
    fp1 = forest_fingerprint(conn)
    fp2 = forest_fingerprint(conn)
    conn.close()
    assert fp1 == fp2 and len(fp1) == 64

def test_fingerprint_changes_on_tamper(db):
    import_forest_to_db(str(EXAMPLE), db)
    conn = open_db(db)
    fp_before = forest_fingerprint(conn)
    conn.execute("UPDATE forest_nodes SET truth_score=0.99 WHERE node_id='E0_Root'")
    conn.commit()
    fp_after = forest_fingerprint(conn)
    conn.close()
    assert fp_before != fp_after

def test_verify_detects_score_mismatch(db, tmp_path):
    import_forest_to_db(str(EXAMPLE), db)
    data = json.loads(EXAMPLE.read_text())
    data["trees"][0]["nodes"][0]["truth_score"] = 0.99
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(data))
    report = verify_file(str(tampered), db)
    assert len(report["score_mismatches"]) > 0
