from __future__ import annotations

from unittest.mock import patch

import pytest

from tradecraft.adapters.crlf_injection_probe.execute import RawCrlfResult
from tradecraft.adapters.http_request.parse import evidence_target_from_url, host_port_from_url
from tradecraft.tools.crlf_injection_probe import CrlfInjectionProbe

EXECUTE_PATH = "tradecraft.tools.crlf_injection_probe.crlf_execute.execute"


class TestCrlfInjectionProbeTool:
    @pytest.fixture
    def tool(self):
        return CrlfInjectionProbe()

    def test_extract_facts_vulnerable(self, tool):
        params = {"target": "https://example.com/redirect?url=/home", "parameter": "url"}
        result = {"vulnerable": True, "evidence_id": "ev-1"}
        facts = tool.extract_facts(params, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["severity"] == "medium"
        assert "url" in fact["vulnerability"]
        assert fact["host"] == host_port_from_url(params["target"])[0]
        assert fact["port"] == host_port_from_url(params["target"])[1]
        assert fact["evidence"] == "ev-1"

    def test_extract_facts_not_vulnerable(self, tool):
        params = {"target": "https://example.com/redirect?url=/home", "parameter": "url"}
        facts = tool.extract_facts(params, {"vulnerable": False})
        assert facts == [{"host": "example.com", "port": 443, "crlf_tested": True}]

    def test_extract_evidence_pops_full_evidence(self, tool):
        params = {"target": "https://example.com/redirect?url=/home", "parameter": "url"}
        full = {"probe_url": "https://example.com/x", "marker": "crlf0", "headers": {"A": "b"}}
        result = {"vulnerable": False, "_full_evidence": full}
        out = tool.extract_evidence(params, result)
        assert out == (evidence_target_from_url(params["target"]) or params["target"], full)
        assert "_full_evidence" not in result

    def test_extract_evidence_missing(self, tool):
        params = {"target": "https://example.com/", "parameter": "url"}
        assert tool.extract_evidence(params, {"vulnerable": False}) is None

    def test_run_passes_args_through(self, tool):
        raw = RawCrlfResult(
            target="https://example.com/redirect?url=/home",
            parameter="url",
            injected_header_name="X-Custom",
            marker="crlf00",
            probe_url="https://example.com/redirect?url=x",
            status_code=200,
            headers={"X-Custom": "crlf00"},
            injected_header_found=True,
        )
        with patch(EXECUTE_PATH, return_value=raw) as mock_exec:
            res = tool.run(
                target="https://example.com/redirect?url=/home",
                parameter="url",
                injected_header_name="X-Custom",
                timeout=7,
            )
        mock_exec.assert_called_once_with(
            target="https://example.com/redirect?url=/home",
            parameter="url",
            injected_header_name="X-Custom",
            timeout=7,
        )
        assert res["vulnerable"] is True
        assert res["_full_evidence"]["headers"] == {"X-Custom": "crlf00"}
        assert res["_full_evidence"]["marker"] == "crlf00"
