"""Unit tests for GitDumper Tool glue, facts extraction, and evidence extraction."""
from unittest.mock import patch

from tradecraft.adapters.gitdumper.execute import RawGitDumperResult
from tradecraft.tools.gitdumper import GitDumper


class TestGitDumperTool:
    @patch("tradecraft.tools.gitdumper.run_gitdumper")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawGitDumperResult(error="git-dumper binary not found on PATH")
        tool = GitDumper()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["git_exposed"] is False
        assert res["total_files_recovered"] == 0
        assert res["error"] == "git-dumper binary not found on PATH"

    @patch("tradecraft.tools.gitdumper.run_gitdumper")
    @patch("tradecraft.tools.gitdumper.parse_gitdumper_output")
    def test_run_not_exposed(self, mock_parse, mock_exec):
        mock_exec.return_value = RawGitDumperResult(stdout="dummy", returncode=1, target_url="https://example.com")
        mock_parse.return_value = {
            "target": "https://example.com",
            "git_exposed": False,
            "total_files_recovered": 0,
            "files": [],
            "recent_commits": [],
        }
        tool = GitDumper()
        res = tool.run(target="https://example.com")
        assert res["git_exposed"] is False
        assert res["total_files_recovered"] == 0
        assert res["files"] == []
        assert "_full_evidence" in res

    @patch("tradecraft.tools.gitdumper.run_gitdumper")
    @patch("tradecraft.tools.gitdumper.parse_gitdumper_output")
    def test_run_exposed_with_omission(self, mock_parse, mock_exec):
        mock_exec.return_value = RawGitDumperResult(stdout="dummy", returncode=0, target_url="https://example.com")
        mock_parse.return_value = {
            "target": "https://example.com",
            "git_exposed": True,
            "total_files_recovered": 20,
            "files": [f"file_{i}.php" for i in range(20)],
            "recent_commits": ["abc1234 - dev: commit"],
        }
        tool = GitDumper()
        res = tool.run(target="https://example.com")
        assert res["git_exposed"] is True
        assert res["total_files_recovered"] == 20
        assert len(res["files"]) == 15
        assert res["omitted_files"] == 5
        assert "5 more files omitted" in res["note"]
        assert len(res["_full_evidence"]["files"]) == 20

    def test_extract_evidence(self):
        tool = GitDumper()
        result = {
            "target": "https://example.com/app",
            "git_exposed": True,
            "_full_evidence": {"target": "https://example.com/app", "git_exposed": True},
        }
        ev = tool.extract_evidence({"target": "https://example.com/app"}, result)
        assert ev is not None
        canonical, full = ev
        assert canonical == "example.com"
        assert full["git_exposed"] is True
        assert "_full_evidence" not in result

    def test_extract_facts_when_not_exposed(self):
        tool = GitDumper()
        result = {"target": "https://example.com", "git_exposed": False, "total_files_recovered": 0}
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert facts == []

    def test_extract_facts_when_exposed(self):
        tool = GitDumper()
        result = {
            "target": "https://example.com:443",
            "git_exposed": True,
            "total_files_recovered": 5,
            "evidence_id": "gitdumper:example.com",
        }
        facts = tool.extract_facts({"target": "https://example.com:443"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 443
        assert fact["git_repository_exposed"] is True
        assert fact["git_recovered_files_count"] == 5
        assert fact["evidence"] == "gitdumper:example.com"
