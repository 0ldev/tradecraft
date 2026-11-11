from unittest.mock import patch

from tradecraft.adapters.gitdorker.execute import RawGitdorkerResult
from tradecraft.tools.gitdorker import GitDorker


def test_tool_attributes():
    tool = GitDorker()
    assert tool.tool_id == "gitdorker"
    assert tool.spec.name == "gitdorker"
    assert tool.scope_param == "target"


def test_tool_run_success():
    tool = GitDorker()
    mock_raw = RawGitdorkerResult(
        csv_rows=[
            ["URL", "Matched Dork"],
            ["https://github.com/target/repo1", "filename:.env password"],
            ["https://github.com/target/repo2", "filename:docker-compose.yml"],
        ]
    )

    with patch("tradecraft.adapters.gitdorker.execute.execute", return_value=mock_raw):
        res = tool.run("target_org")
        assert res["target"] == "target_org"
        assert res["total_findings"] == 2
        assert len(res["findings"]) == 2
        assert res["findings"][0]["type"] == "secret"
        assert res["findings"][1]["type"] == "repo"
        assert "_full_evidence" in res


def test_tool_run_omitted_findings_over_20():
    tool = GitDorker()
    rows = [["URL", "Matched Dork"]] + [
        [f"https://github.com/target/repo{i}", "dork"] for i in range(25)
    ]
    mock_raw = RawGitdorkerResult(csv_rows=rows)

    with patch("tradecraft.adapters.gitdorker.execute.execute", return_value=mock_raw):
        res = tool.run("target_org")
        assert res["total_findings"] == 25
        assert len(res["findings"]) == 20
        assert res["omitted_findings"] == 5
        assert "5 more omitted" in res["note"]


def test_tool_run_error():
    tool = GitDorker()
    mock_raw = RawGitdorkerResult(error="GITHUB_TOKEN environment variable not set")

    with patch("tradecraft.adapters.gitdorker.execute.execute", return_value=mock_raw):
        res = tool.run("target_org")
        assert res["error"] == "GITHUB_TOKEN environment variable not set"
        assert res["total_findings"] == 0


def test_extract_evidence():
    tool = GitDorker()
    params = {"target": "target_org"}
    result = {
        "target": "target_org",
        "findings": [],
        "_full_evidence": {"data": 123},
    }
    extracted = tool.extract_evidence(params, result)
    assert extracted is not None
    target_key, full = extracted
    assert target_key == "target_org"
    assert "_full_evidence" not in result


def test_extract_facts():
    tool = GitDorker()
    # GitDorker produces no (host, port) network facts
    assert tool.extract_facts({"target": "target"}, {"findings": [{"url": "http://..."}]}) == []
