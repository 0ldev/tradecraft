"""
Unit tests for magento_cosmicsting_probe adapter and tool.
Mocks all network calls so tests run fully offline.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from tradecraft.adapters.magento_cosmicsting_probe.execute import (
    EndpointProbeResult,
    RawCosmicStingResult,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.magento_cosmicsting_probe.parse import parse_cosmicsting_result
from tradecraft.tools.magento_cosmicsting_probe import MagentoCosmicStingProbe
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS


class TestMagentoCosmicStingExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("example.com") == "https://example.com"
        assert normalize_target_url("http://shop.example.com/") == "http://shop.example.com"
        assert normalize_target_url("  https://store.local/magento  ") == "https://store.local/magento"

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "target is required"
        assert not res.probes

    @patch("requests.Session")
    def test_execute_vulnerable_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        # Guest cart endpoint 404
        cart_resp = MagicMock()
        cart_resp.status_code = 404
        mock_session.post.side_effect = [
            cart_resp,
            # estimate-shipping-methods returns XML I/O warning
            MagicMock(
                status_code=500,
                text="DOMDocument::loadXML(): I/O warning : failed to load external entity",
            ),
        ]

        result = execute("https://vulnerable-magento.test")
        assert result.target == "https://vulnerable-magento.test"
        assert result.cart_id_used == "default"
        assert len(result.probes) == 1
        assert result.probes[0].is_vulnerable_indicator is True
        assert result.probes[0].is_patched_indicator is False

    @patch("requests.Session")
    def test_execute_patched_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        cart_resp = MagicMock()
        cart_resp.status_code = 404
        mock_session.post.side_effect = [
            cart_resp,
            MagicMock(
                status_code=400,
                text='{"message":"Property \\"totalsCollector\\" does not have accessor method"}',
            ),
        ]

        result = execute("https://patched-magento.test")
        assert len(result.probes) == 1
        assert result.probes[0].is_vulnerable_indicator is False
        assert result.probes[0].is_patched_indicator is True

    @patch("requests.Session")
    def test_execute_guest_cart_creation(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        cart_resp = MagicMock()
        cart_resp.status_code = 200
        cart_resp.json.return_value = "cart_uuid_987654321"

        probe_resp = MagicMock()
        probe_resp.status_code = 404
        probe_resp.text = "Not Found"

        mock_session.post.side_effect = [cart_resp, probe_resp, probe_resp, probe_resp]

        result = execute("https://magento-store.test")
        assert result.guest_cart_created is True
        assert result.cart_id_used == "cart_uuid_987654321"
        assert len(result.probes) == 3

    @patch("requests.Session")
    def test_execute_network_error(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_session.post.side_effect = requests.exceptions.ConnectionError("Connection failed")

        result = execute("https://offline-target.test")
        assert len(result.probes) == 3
        for p in result.probes:
            assert p.error is not None
            assert "Connection failed" in p.error


class TestMagentoCosmicStingParse:
    def test_parse_vulnerable_result(self):
        raw = RawCosmicStingResult(
            target="https://magento.test",
            callback_url="http://127.0.0.1:54321/cosmicsting_probe.dtd",
            cart_id_used="cart123",
            guest_cart_created=True,
            probes=[
                EndpointProbeResult(
                    url="https://magento.test/rest/V1/guest-carts/cart123/estimate-shipping-methods",
                    status_code=500,
                    body_snippet="I/O warning : failed to load external entity",
                    is_vulnerable_indicator=True,
                )
            ],
        )
        parsed = parse_cosmicsting_result(raw)
        assert parsed["vulnerable"] is True
        assert parsed["patched"] is False
        assert parsed["status"] == "vulnerable"
        assert "CVE-2024-34102" in parsed["summary"]
        assert "APSB24-40" in parsed["recommendation"]

    def test_parse_patched_result(self):
        raw = RawCosmicStingResult(
            target="https://magento.test",
            cart_id_used="cart123",
            probes=[
                EndpointProbeResult(
                    url="https://magento.test/rest/V1/guest-carts/cart123/estimate-shipping-methods",
                    status_code=400,
                    body_snippet='Property "TotalsCollector" does not have accessor method',
                    is_patched_indicator=True,
                )
            ],
        )
        parsed = parse_cosmicsting_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["patched"] is True
        assert parsed["status"] == "patched"
        assert "PATCHED" in parsed["summary"]

    def test_parse_not_applicable_404(self):
        raw = RawCosmicStingResult(
            target="https://magento.test",
            probes=[
                EndpointProbeResult(
                    url="https://magento.test/rest/V1/guest-carts/default/estimate-shipping-methods",
                    status_code=404,
                ),
                EndpointProbeResult(
                    url="https://magento.test/rest/default/V1/guest-carts/default/estimate-shipping-methods",
                    status_code=404,
                ),
            ],
        )
        parsed = parse_cosmicsting_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "not_applicable"
        assert "NOT_APPLICABLE" in parsed["summary"]

    def test_parse_inconclusive(self):
        raw = RawCosmicStingResult(
            target="https://magento.test",
            probes=[
                EndpointProbeResult(
                    url="https://magento.test/rest/V1/guest-carts/default/estimate-shipping-methods",
                    status_code=200,
                    body_snippet='[]',
                )
            ],
        )
        parsed = parse_cosmicsting_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "inconclusive"

    def test_parse_error(self):
        raw = RawCosmicStingResult(target="https://magento.test", error="target is required")
        parsed = parse_cosmicsting_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "error"
        assert parsed["error"] == "target is required"


class TestMagentoCosmicStingTool:
    def test_registration(self):
        ids = [t.tool_id for t in ALL_TOOLS]
        assert "magento_cosmicsting_probe" in ids

    def test_spec_attributes(self):
        tool = MagentoCosmicStingProbe()
        assert tool.spec.name == "magento_cosmicsting_probe"
        assert tool.required_binary is None
        assert tool.scope_param == "target"
        assert tool.destructive is False
        assert tool.is_available() is True
        assert "target" in tool.spec.parameters["properties"]

    @patch("tradecraft.adapters.magento_cosmicsting_probe.execute.execute")
    def test_tool_run(self, mock_exec):
        mock_exec.return_value = RawCosmicStingResult(
            target="https://example.com",
            probes=[],
        )
        tool = MagentoCosmicStingProbe()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["vulnerable"] is False

    def test_profile_membership(self):
        web = load_profile("web")
        full = load_profile("full")
        assert "magento_cosmicsting_probe" in web
        assert "magento_cosmicsting_probe" in full
