"""Tests for Phase 3: Craft Studio data layer (pure parts, no server)."""
import json

from tradecraft.studio.data import list_runs, parse_log, run_data


def _run_dir(tmp_path):
    run = tmp_path / "targets" / "10.0.0.5" / "runs" / "run-001"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text(json.dumps({
        "run_id": "run-001", "target": "10.0.0.5", "model": "test-model",
        "turns_used": 7, "findings_count": 2,
    }))
    (run / "log.txt").write_text("\n".join([
        "FINDING #1 [evidence: nmap_scan:10.0.0.5]: port 80 open",
        "note: started with httpx",
        "FINDING #2 [unverified: no evidence_id]: admin panel looks default",
        "Finding #1 retracted: wrong",  # lower-case -> lands in notes (tolerant parser)
    ]))
    (run / "facts.json").write_text(json.dumps({
        "records": [
            {"host": "10.0.0.5", "port": 80, "http_title": "Login",
             "params_discovered": "q", "sqli_tested": True},
            {"host": "10.0.0.5", "port": 443, "http_title": "Admin"},
        ]
    }))
    return run


def test_parse_log_splits_findings_and_notes(tmp_path):
    run = _run_dir(tmp_path)
    parsed = parse_log(run / "log.txt")
    assert len(parsed["findings"]) == 2
    assert parsed["findings"][0]["finding_id"] == 1
    assert any("httpx" in n for n in parsed["notes"])


def test_run_data_builds_coverage_matrix(tmp_path):
    run = _run_dir(tmp_path)
    data = run_data(run)
    assert data["manifest"]["target"] == "10.0.0.5"
    assert data["coverage"] is not None
    targets = [row["target"] for row in data["coverage"]["rows"]]
    assert "10.0.0.5:80" in targets and "10.0.0.5:443" in targets
    cells = data["coverage"]["rows"][0]["cells"]
    assert cells["sqli"] == "clean"


def test_run_data_missing_dir_is_safe(tmp_path):
    data = run_data(tmp_path / "nope")
    assert data["exists"] is False
    assert data["coverage"] is None


def test_list_runs_scans_home(tmp_path):
    _run_dir(tmp_path)
    runs = list_runs(tmp_path)
    assert len(runs) == 1
    assert runs[0]["run_id"] == "run-001"
    assert runs[0]["target"] == "10.0.0.5"


def test_list_runs_empty_home(tmp_path):
    assert list_runs(tmp_path) == []
