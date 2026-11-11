"""Unit tests for the jupyter_exposure_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.jupyter_exposure_probe.execute import RawJupyterResult
from tradecraft.tools.jupyter_exposure_probe import JupyterExposureProbe


def test_tool_attributes():
    tool = JupyterExposureProbe()
    assert tool.tool_id == "jupyter_exposure_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = JupyterExposureProbe()
    failed = RawJupyterResult(target="down.example", error="connection refused")
    with patch("tradecraft.tools.jupyter_exposure_probe.jupyter_execute.execute", return_value=failed):
        result = tool.run(target="down.example")
    assert result["error"] == "connection refused"
    assert "_full_evidence" not in result


def test_run_vulnerable_builds_evidence_and_facts():
    tool = JupyterExposureProbe()
    raw = RawJupyterResult(
        target="notebook.local",
        host="notebook.local",
        port=8888,
        service="jupyter",
        connected=True,
        version="6.5.4",
        vulnerable=True,
        status="vulnerable",
        kernels_listed=0,
    )
    with patch("tradecraft.tools.jupyter_exposure_probe.jupyter_execute.execute", return_value=raw):
        result = tool.run(target="notebook.local")

    assert result["vulnerable"] is True
    assert "_full_evidence" in result
    facts = tool.extract_facts({"target": "notebook.local"}, dict(result))
    assert len(facts) == 1
    assert facts[0]["service"] == "jupyter"
    assert facts[0]["version"] == "6.5.4"
    assert facts[0]["severity"] == "critical"

    extracted = tool.extract_evidence({"target": "notebook.local"}, result)
    assert extracted is not None
    assert extracted[0] == "notebook.local"


def test_extract_facts_empty_when_not_vulnerable():
    tool = JupyterExposureProbe()
    assert tool.extract_facts({"target": "notebook.local"}, {"vulnerable": False}) == []
    assert tool.extract_evidence({"target": "notebook.local"}, {"vulnerable": False}) is None
