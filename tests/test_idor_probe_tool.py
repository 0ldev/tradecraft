from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.idor_probe.execute import RawHttpResponse, RawIdorResult
from tradecraft.tools.idor_probe import IdorProbe


class TestIdorProbeTool:
    def test_tool_metadata(self):
        tool = IdorProbe()
        assert tool.tool_id == "idor_probe"
        assert tool.scope_param == "target"
        assert tool.is_available() is True

    @patch("tradecraft.tools.idor_probe.idor_execute.execute")
    def test_run_success(self, mock_exec):
        base_resp = RawHttpResponse(
            url="https://example.com/api/orders?id=105",
            tested_id="105",
            status_code=200,
            body='{"id": 105, "order": "A"}',
            body_length=25,
        )
        probe1 = RawHttpResponse(
            url="https://example.com/api/orders?id=106",
            tested_id="106",
            status_code=200,
            body='{"id": 106, "order": "B"}',
            body_length=25,
        )
        mock_exec.return_value = RawIdorResult(
            target="https://example.com/api/orders?id=105",
            param="id",
            baseline_id="105",
            baseline_response=base_resp,
            probes=[probe1],
        )

        tool = IdorProbe()
        result = tool.run(target="https://example.com/api/orders?id=105")

        assert result["target"] == "https://example.com/api/orders?id=105"
        assert result["potential_idor_detected"] is True
        assert len(result["probes"]) == 1
        assert "_full_evidence" in result

        # Test evidence extraction
        ev = tool.extract_evidence({"target": "https://example.com/api/orders?id=105"}, result)
        assert ev is not None
        host, full = ev
        assert host == "example.com"
        assert full["baseline_id"] == "105"
        assert len(full["probes"]) == 1
        assert "_full_evidence" not in result  # popped cleanly

        # Test facts extraction (semantic judgment left to model)
        facts = tool.extract_facts({"target": "https://example.com/api/orders?id=105"}, result)
        assert facts == []

    @patch("tradecraft.tools.idor_probe.idor_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawIdorResult(
            target="https://example.com/about",
            error="No object identifier found in target URL",
        )

        tool = IdorProbe()
        result = tool.run(target="https://example.com/about")
        assert result["target"] == "https://example.com/about"
        assert "No object identifier found" in result["error"]
