from unittest.mock import patch

from tradecraft.adapters.ffuf.execute import CanarySignature
from tradecraft.adapters.ffuf_vhost.execute import RawVhostResult
from tradecraft.tools.ffuf_vhost import FfufVhost


def test_ffuf_vhost_run_error():
    tool = FfufVhost()
    with patch("tradecraft.adapters.ffuf_vhost.execute.execute") as mock_exec:
        mock_exec.return_value = RawVhostResult(error="ffuf binary not found")
        res = tool.run("example.com")
        assert res["target"] == "example.com"
        assert res["vhosts_found"] == 0
        assert res["vhosts"] == []
        assert res["error"] == "ffuf binary not found"


def test_ffuf_vhost_run_success():
    tool = FfufVhost()
    with patch("tradecraft.adapters.ffuf_vhost.execute.execute") as mock_exec:
        mock_exec.return_value = RawVhostResult(
            json_output='{"results": [{"input": {"FUZZ": "api"}, "status": 200, "length": 300}]}',
            baseline=CanarySignature(status_code=404, length=100),
            host="example.com",
            port=443,
        )
        res = tool.run("example.com")
        assert res["target"] == "example.com"
        assert res["vhosts_found"] == 1
        assert res["vhosts"] == [{"vhost": "api.example.com", "status_code": 200}]
        assert "_full_evidence" in res


def test_ffuf_vhost_run_truncation():
    tool = FfufVhost()
    many_results = [
        {"input": {"FUZZ": f"vhost{i}"}, "status": 200, "length": 300}
        for i in range(20)
    ]
    import json
    with patch("tradecraft.adapters.ffuf_vhost.execute.execute") as mock_exec:
        mock_exec.return_value = RawVhostResult(
            json_output=json.dumps({"results": many_results}),
            baseline=None,
            host="example.com",
            port=443,
        )
        res = tool.run("example.com")
        assert res["vhosts_found"] == 20
        assert len(res["vhosts"]) == 15
        assert res["omitted_vhosts"] == 5
        assert "omitted" in res["note"]


def test_ffuf_vhost_extract_evidence():
    tool = FfufVhost()
    res = {
        "target": "https://example.com",
        "vhosts_found": 1,
        "vhosts": [{"vhost": "admin.example.com", "status_code": 200}],
        "_full_evidence": {
            "target": "https://example.com",
            "host": "example.com",
            "port": 443,
            "vhosts_found": 1,
            "vhosts": [{"vhost": "admin.example.com", "status_code": 200}],
            "baseline": {"status_code": 404, "length": 100},
        },
    }
    host, evidence = tool.extract_evidence({"target": "https://example.com"}, res)
    assert host == "example.com"
    assert evidence["vhosts_found"] == 1
    assert "_full_evidence" not in res


def test_ffuf_vhost_extract_facts():
    tool = FfufVhost()
    res = {
        "target": "https://example.com",
        "vhosts_found": 1,
        "vhosts": [{"vhost": "admin.example.com", "status_code": 200}],
        "evidence_id": "ev_123",
    }
    facts = tool.extract_facts({"target": "https://example.com"}, res)
    assert len(facts) == 1
    assert facts[0] == {
        "host": "admin.example.com",
        "port": 443,
        "vhost_discovered_via": "example.com",
        "http_status": 200,
        "evidence": "ev_123",
    }
