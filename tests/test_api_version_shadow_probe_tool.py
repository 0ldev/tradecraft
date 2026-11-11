"""Unit tests for the api_version_shadow_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.api_version_shadow_probe.execute import (
    RawApiVersionShadowResult,
    RawApiVersionVariant,
)
from tradecraft.tools.api_version_shadow_probe import ApiVersionShadowProbe


def _vulnerable_raw():
    return RawApiVersionShadowResult(
        target="https://api.example.com/v2/users",
        method="GET",
        baseline_status=401,
        baseline_length=6,
        baseline_was_blocked=True,
        variants=[
            RawApiVersionVariant(
                label="replace_v2_with_v1",
                url="https://api.example.com/v1/users",
                status=200,
                body_length=2,
            ),
            RawApiVersionVariant(
                label="replace_v2_with_v0",
                url="https://api.example.com/v0/users",
                status=401,
                body_length=6,
            ),
        ],
    )


def test_tool_attributes():
    tool = ApiVersionShadowProbe()
    assert tool.tool_id == "api_version_shadow_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = ApiVersionShadowProbe()
    failed = RawApiVersionShadowResult(target="https://down.example", error="boom")
    with patch("tradecraft.tools.api_version_shadow_probe.shadow_execute.execute", return_value=failed):
        result = tool.run(target="https://down.example")
    assert result == {"target": "https://down.example", "error": "boom"}


def test_run_vulnerable_builds_evidence_and_facts():
    tool = ApiVersionShadowProbe()
    with patch(
        "tradecraft.tools.api_version_shadow_probe.shadow_execute.execute",
        return_value=_vulnerable_raw(),
    ):
        result = tool.run(target="https://api.example.com/v2/users")

    assert result["vulnerable"] is True
    assert "_full_evidence" in result
    facts = tool.extract_facts({"target": "https://api.example.com/v2/users"}, dict(result))
    assert len(facts) == 1
    assert facts[0]["host"] == "api.example.com"
    assert facts[0]["port"] == 443
    assert "replace_v2_with_v1" in facts[0]["vulnerability"]
    assert facts[0]["severity"] == "high"

    extracted = tool.extract_evidence({"target": "https://api.example.com/v2/users"}, result)
    assert extracted is not None
    assert extracted[0] == "api.example.com"


def test_extract_facts_empty_when_not_vulnerable():
    tool = ApiVersionShadowProbe()
    params = {"target": "https://api.example.com/v2/users"}
    assert tool.extract_facts(params, {"vulnerable": False}) == []
    assert tool.extract_evidence(params, {"vulnerable": False}) is None
