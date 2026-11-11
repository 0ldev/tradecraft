"""Unit tests for the dependency_confusion_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.dependency_confusion_probe.execute import RawDependencyConfusionResult
from tradecraft.tools.dependency_confusion_probe import DependencyConfusionProbe


def test_tool_attributes():
    tool = DependencyConfusionProbe()
    assert tool.tool_id == "dependency_confusion_probe"
    assert tool.scope_param is None
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = DependencyConfusionProbe()
    failed = RawDependencyConfusionResult(error="no valid package names provided")
    with patch("tradecraft.tools.dependency_confusion_probe.dcp_execute.execute", return_value=failed):
        result = tool.run(packages="   ")
    assert result == {"error": "no valid package names provided"}


def test_extract_evidence_uses_first_package_name():
    tool = DependencyConfusionProbe()
    params = {"packages": "acme-internal-utils:npm,other-pkg:pypi"}
    result = {"squattable_count": 1, "_full_evidence": {"raw": "data"}}
    extracted = tool.extract_evidence(params, result)
    assert extracted is not None
    key, full = extracted
    assert key == "acme-internal-utils"
    assert "_full_evidence" not in result


def test_extract_facts_always_empty():
    tool = DependencyConfusionProbe()
    assert tool.extract_facts({}, {"squattable_count": 1}) == []
