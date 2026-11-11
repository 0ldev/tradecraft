from unittest.mock import MagicMock, patch

from tradecraft.adapters.linkfinder.execute import RawLinkfinderResult
from tradecraft.tools.linkfinder import LinkFinder


def test_linkfinder_is_available():
    tool = LinkFinder()
    with patch("shutil.which") as mock_which, patch("tradecraft.adapters.linkfinder.execute.find_script") as mock_find:
        mock_which.return_value = "/usr/bin/python3"
        mock_find.return_value = "/opt/LinkFinder/linkfinder.py"
        assert tool.is_available() is True

        mock_find.return_value = None
        assert tool.is_available() is False


def test_linkfinder_run_error():
    tool = LinkFinder()
    with patch("tradecraft.adapters.linkfinder.execute.execute") as mock_exec:
        mock_exec.return_value = RawLinkfinderResult(error="LinkFinder not found")
        res = tool.run("example.com")
        assert res["target"] == "example.com"
        assert res["endpoints_discovered"] == []
        assert res["error"] == "LinkFinder not found"


def test_linkfinder_run_success():
    tool = LinkFinder()
    with patch("tradecraft.adapters.linkfinder.execute.execute") as mock_exec:
        mock_exec.return_value = RawLinkfinderResult(
            stdout="/api/v1/auth\n/api/v1/user\n",
            returncode=0,
            target_url="https://example.com",
        )
        res = tool.run("example.com")
        assert res["target"] == "example.com"
        assert res["endpoints_discovered"] == ["/api/v1/auth", "/api/v1/user"]
        assert "_full_evidence" in res


def test_linkfinder_run_truncation():
    tool = LinkFinder()
    many_endpoints = "\n".join(f"/api/endpoint_{i:02d}" for i in range(40))
    with patch("tradecraft.adapters.linkfinder.execute.execute") as mock_exec:
        mock_exec.return_value = RawLinkfinderResult(
            stdout=many_endpoints,
            returncode=0,
            target_url="https://example.com",
        )
        res = tool.run("example.com")
        assert len(res["endpoints_discovered"]) == 30
        assert res["omitted_endpoints"] == 10
        assert "10 more omitted" in res["note"]
        assert len(res["_full_evidence"]["endpoints_discovered"]) == 40


def test_linkfinder_extract_evidence():
    tool = LinkFinder()
    res = {
        "target": "https://example.com/app",
        "endpoints_discovered": ["/api/v1"],
        "_full_evidence": {
            "target": "https://example.com/app",
            "endpoints_discovered": ["/api/v1"],
            "raw_output": "/api/v1\n",
        },
    }
    host, evidence = tool.extract_evidence({"target": "https://example.com/app"}, res)
    assert host == "example.com"
    assert evidence["endpoints_discovered"] == ["/api/v1"]
    assert "_full_evidence" not in res


def test_linkfinder_extract_facts():
    tool = LinkFinder()
    res = {
        "target": "https://example.com:8443/app",
        "endpoints_discovered": ["/api/v1"],
        "evidence_id": "ev_abc",
    }
    facts = tool.extract_facts({"target": "https://example.com:8443/app"}, res)
    assert len(facts) == 1
    assert facts[0] == {
        "host": "example.com",
        "port": 8443,
        "js_endpoints_found": 1,
        "evidence": "ev_abc",
    }
