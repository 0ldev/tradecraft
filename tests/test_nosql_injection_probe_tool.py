"""
Tool-layer tests for nosql_injection_probe: the adapter's execute() is
patched at the tool module, so these test glue only (params pass-through,
evidence/fact extraction), not HTTP behaviour.
"""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.nosql_injection_probe.execute import RawNoSqlInjectionResult, RawNoSqlResponse
from tradecraft.tools.nosql_injection_probe import NosqlInjectionProbe

TARGET = "https://example.com/api/login"


def _vulnerable_result() -> dict:
    return {
        "target": TARGET,
        "field": "username",
        "baseline_status": 401,
        "tested_operators": ["$ne", "$gt"],
        "anomalous_operators": ["$ne"],
        "anomalies": [{"operator": "$ne"}],
        "vulnerable": True,
        "error": None,
    }


class TestToolMetadata:
    def test_tool_id_and_scope(self):
        tool = NosqlInjectionProbe()
        assert tool.tool_id == "nosql_injection_probe"
        assert tool.scope_param == "target"
        assert tool.spec.name == "nosql_injection_probe"


class TestRunPassThrough:
    @patch("tradecraft.tools.nosql_injection_probe.nosql_execute.execute")
    def test_run_passes_all_params_unchanged(self, mock_exec):
        mock_exec.return_value = RawNoSqlInjectionResult(target=TARGET, field="username")
        NosqlInjectionProbe().run(
            target=TARGET,
            body='{"username": "a"}',
            field="username",
            headers="X-Test: 1",
            timeout=7,
        )
        mock_exec.assert_called_once_with(
            target=TARGET,
            body='{"username": "a"}',
            field="username",
            headers="X-Test: 1",
            timeout=7,
        )

    @patch("tradecraft.tools.nosql_injection_probe.nosql_execute.execute")
    def test_run_returns_parsed_result_with_full_evidence(self, mock_exec):
        mock_exec.return_value = RawNoSqlInjectionResult(
            target=TARGET,
            field="username",
            baseline_response=RawNoSqlResponse(operator="baseline", status_code=401, body="nope", body_length=4),
            probes=[RawNoSqlResponse(operator="$ne", status_code=200, body='{"token":"x"}', body_length=13)],
        )
        result = NosqlInjectionProbe().run(target=TARGET, body='{"username": "a"}', field="username")
        assert result["vulnerable"] is True
        assert result["anomalous_operators"] == ["$ne"]
        assert result["_full_evidence"]["baseline"]["body"] == "nope"
        assert result["_full_evidence"]["probes"][0]["body"] == '{"token":"x"}'


class TestExtractEvidence:
    def test_pops_full_evidence_and_returns_canonical_target(self):
        tool = NosqlInjectionProbe()
        result = {"vulnerable": False, "_full_evidence": {"field": "username", "probes": []}}
        ev = tool.extract_evidence({"target": TARGET}, result)
        assert ev is not None
        key, full = ev
        assert key == "example.com/api/login"
        assert full == {"field": "username", "probes": []}
        assert "_full_evidence" not in result

    def test_returns_none_when_evidence_missing(self):
        tool = NosqlInjectionProbe()
        assert tool.extract_evidence({"target": TARGET}, {"vulnerable": False}) is None

    def test_returns_none_when_target_missing(self):
        tool = NosqlInjectionProbe()
        assert tool.extract_evidence({}, {"_full_evidence": {}}) is None


class TestExtractFacts:
    def test_vulnerable_emits_one_high_severity_fact(self):
        tool = NosqlInjectionProbe()
        facts = tool.extract_facts({"target": TARGET, "field": "username"}, _vulnerable_result())
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 443
        assert fact["severity"] == "high"
        assert "username" in fact["vulnerability"]
        assert "$ne" in fact["vulnerability"]
        assert "evidence" not in fact

    def test_vulnerable_fact_links_evidence_id(self):
        tool = NosqlInjectionProbe()
        result = _vulnerable_result()
        result["evidence_id"] = "ev-123"
        facts = tool.extract_facts({"target": TARGET, "field": "username"}, result)
        assert facts[0]["evidence"] == "ev-123"

    def test_not_vulnerable_emits_tested_fact(self):
        tool = NosqlInjectionProbe()
        result = {"vulnerable": False, "anomalous_operators": []}
        assert tool.extract_facts({"target": TARGET, "field": "username"}, result) == [
            {"host": "example.com", "port": 443, "nosql_tested": True}
        ]
