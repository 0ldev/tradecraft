from __future__ import annotations

from unittest.mock import patch

import pytest

from tradecraft.adapters.race_condition_probe.execute import RaceAttempt, RawRaceConditionResult
from tradecraft.tools.race_condition_probe import RaceConditionProbe

TOOL_MODULE = "tradecraft.tools.race_condition_probe"


def _raw(likely: bool, success_count: int, url: str = "https://shop.example.com/api/redeem") -> RawRaceConditionResult:
    return RawRaceConditionResult(
        url=url,
        method="POST",
        requested_count=5,
        attempts=[
            RaceAttempt(index=i, status_code=200, body_snippet=f"body {i}", success_marker_found=i < success_count,
                        duration_seconds=0.01)
            for i in range(5)
        ],
        success_count=success_count,
        likely_race_condition=likely,
    )


@pytest.fixture
def tool():
    return RaceConditionProbe()


class TestRaceConditionProbeTool:
    def test_extract_facts_when_race_detected(self, tool):
        params = {"url": "https://shop.example.com/api/redeem"}
        result = {
            "url": "https://shop.example.com/api/redeem",
            "likely_race_condition": True,
            "success_count": 3,
            "evidence_id": "ev-1",
        }
        facts = tool.extract_facts(params, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "shop.example.com"
        assert fact["port"] == 443
        assert fact["severity"] == "high"
        assert fact["race_success_count"] == 3
        assert fact["evidence"] == "ev-1"
        assert "vulnerability" in fact

    def test_extract_facts_when_no_race_returns_empty(self, tool):
        params = {"url": "https://shop.example.com/api/redeem"}
        result = {
            "url": "https://shop.example.com/api/redeem",
            "likely_race_condition": False,
            "success_count": 1,
        }
        assert tool.extract_facts(params, result) == []

    def test_extract_facts_without_url_returns_empty(self, tool):
        assert tool.extract_facts({}, {"likely_race_condition": True, "url": ""}) == []

    def test_extract_evidence_bare_host(self, tool):
        params = {"url": "https://shop.example.com"}
        result = {"_full_evidence": {"url": "https://shop.example.com"}}
        target, data = tool.extract_evidence(params, result)
        assert target == "shop.example.com"
        assert data == {"url": "https://shop.example.com"}
        assert "_full_evidence" not in result

    def test_extract_evidence_url_with_path(self, tool):
        params = {"url": "https://shop.example.com/api/redeem"}
        result = {"_full_evidence": {"url": "https://shop.example.com/api/redeem"}}
        target, _ = tool.extract_evidence(params, result)
        assert target == "shop.example.com/api/redeem"
        assert "_full_evidence" not in result

    def test_extract_evidence_missing_full_returns_none(self, tool):
        assert tool.extract_evidence({"url": "https://shop.example.com"}, {}) is None

    def test_run_passes_all_parameters_through(self, tool):
        with patch(f"{TOOL_MODULE}.run_race_condition_probe", return_value=_raw(True, 5)) as mock_exec:
            tool.run(
                url="https://shop.example.com/api/redeem",
                method="PUT",
                headers="Cookie: session=abc",
                data='{"code":"X"}',
                request_count=7,
                success_marker="redeemed",
                timeout=4,
            )

        kwargs = mock_exec.call_args.kwargs
        assert kwargs == {
            "url": "https://shop.example.com/api/redeem",
            "method": "PUT",
            "headers": "Cookie: session=abc",
            "data": '{"code":"X"}',
            "request_count": 7,
            "success_marker": "redeemed",
            "timeout": 4,
        }

    def test_run_attaches_full_evidence_with_all_attempts(self, tool):
        with patch(f"{TOOL_MODULE}.run_race_condition_probe", return_value=_raw(True, 5)):
            out = tool.run(url="https://shop.example.com/api/redeem")

        assert out["likely_race_condition"] is True
        assert len(out["attempts"]) == 5
        assert "body_snippet" not in out["attempts"][0]
        full = out["_full_evidence"]
        assert len(full["attempts"]) == 5
        assert full["attempts"][0]["body_snippet"] == "body 0"
