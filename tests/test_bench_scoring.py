"""Tests for the Phase 0 bench harness (pure scoring parts)."""
import pytest

from bench.scoring import efficiency, render_summary, score_findings


def test_score_full_match():
    findings = ["SQL injection confirmed on login endpoint", "XSS in search"]
    expected = [
        {"id": "sqli", "keywords": ["sql", "login"]},
        {"id": "xss", "keywords": ["xss"]},
    ]
    result = score_findings(findings, expected)
    assert result["recall"] == 1.0
    assert result["matched_ids"] == ["sqli", "xss"]
    assert result["missed"] == []


def test_score_partial_match():
    findings = ["XSS in search"]
    expected = [
        {"id": "sqli", "keywords": ["sql"]},
        {"id": "xss", "keywords": ["xss"]},
    ]
    result = score_findings(findings, expected)
    assert result["recall"] == 0.5
    assert result["missed"][0]["id"] == "sqli"


def test_score_all_keywords_required():
    # "sql" alone must NOT match a group requiring ["sql", "login"].
    result = score_findings(["sql found somewhere"], [{"id": "g", "keywords": ["sql", "login"]}])
    assert result["recall"] == 0.0


def test_score_case_insensitive():
    result = score_findings(["XSS in SEARCH"], [{"id": "x", "keywords": ["xss", "search"]}])
    assert result["recall"] == 1.0


def test_score_empty_expected():
    assert score_findings([], [])["recall"] == 0.0


def test_efficiency_zero_recall():
    eff = efficiency(0.0, 10, 0)
    assert eff["turns_per_recall_point"] == 0.0
    eff = efficiency(0.5, 10, 5)
    assert eff["findings_per_turn"] == 0.5
    assert eff["turns_per_recall_point"] == 20.0


def test_render_summary():
    results = [{
        "lab": "lab-a", "recall": 0.5, "total_expected": 2,
        "matched": [{"id": "x"}], "missed": [{"id": "y"}],
        "turns_used": 12, "findings_count": 3,
    }]
    text = render_summary(results)
    assert "| lab-a | 50% |" in text
    assert "Mean recall: 50%" in text
    assert "missed in lab-a: y" in text
    assert render_summary([]) == "_(no bench results)_"


def test_load_config_validates():
    from bench.run_bench import load_config
    import tempfile, pathlib
    bad = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    bad.write("labs: []\n")
    bad.close()
    with pytest.raises(ValueError):
        load_config(bad.name)
    with pytest.raises(ValueError):
        load_config("/nonexistent.yaml")
