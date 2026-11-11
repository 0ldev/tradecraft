"""
Unit tests for perimeter_gateway_probe adapter and tool.
Mocks all network calls so tests run fully offline.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from tradecraft.adapters.perimeter_gateway_probe.execute import (
    ApplianceProbeResult,
    RawPerimeterResult,
    execute,
    normalize_target_url,
    probe_checkpoint,
    probe_citrix,
    probe_fortinet,
    probe_ivanti,
    probe_paloalto,
)
from tradecraft.adapters.perimeter_gateway_probe.parse import parse_perimeter_result
from tradecraft.tools.perimeter_gateway_probe import PerimeterGatewayProbe
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS


class TestPerimeterGatewayExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("vpn.corp.com") == "https://vpn.corp.com"
        assert normalize_target_url("http://gateway.test:8443/") == "http://gateway.test:8443"
        assert normalize_target_url("  https://10.0.0.1  ") == "https://10.0.0.1"

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "target is required"
        assert not res.results

    def test_probe_checkpoint_vulnerable(self):
        session = MagicMock()
        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.text = "root:x:0:0:root:/root:/bin/bash\nadmin:x:0:0:admin:/home/admin:/bin/bash\n"
        session.post.return_value = post_resp

        res = probe_checkpoint(session, "https://cp-gateway.test", timeout=5)
        assert res.appliance == "checkpoint"
        assert res.vulnerable is True
        assert res.fingerprinted is True
        assert "root:x:0:0" in res.evidence_snippet

    def test_probe_checkpoint_safe(self):
        session = MagicMock()
        post_resp = MagicMock()
        post_resp.status_code = 404
        post_resp.text = "Not Found"
        session.post.return_value = post_resp

        get_resp = MagicMock()
        get_resp.status_code = 200
        get_resp.text = "<html>Generic Gateway</html>"
        get_resp.headers = {}
        session.get.return_value = get_resp

        res = probe_checkpoint(session, "https://cp-gateway.test", timeout=5)
        assert res.appliance == "checkpoint"
        assert res.vulnerable is False
        assert res.fingerprinted is False

    def test_probe_paloalto_vulnerable(self):
        session = MagicMock()
        # Login page responds with GlobalProtect banner
        login_resp = MagicMock()
        login_resp.status_code = 200
        login_resp.text = "<html><title>GlobalProtect Portal Login</title></html>"

        # hipreport responds 200 to traversal SESSID
        hip_resp = MagicMock()
        hip_resp.status_code = 200
        hip_resp.text = "<response status='success'></response>"

        session.get.return_value = login_resp
        session.post.return_value = hip_resp

        res = probe_paloalto(session, "https://pa-gateway.test", timeout=5)
        assert res.appliance == "paloalto"
        assert res.fingerprinted is True
        assert res.vulnerable is True
        assert "CVE-2024-3400" in res.cve

    def test_probe_ivanti_vulnerable(self):
        session = MagicMock()
        fp_resp = MagicMock()
        fp_resp.status_code = 200
        fp_resp.text = "<html>Welcome to Pulse Secure / Ivanti Connect Secure</html>"
        fp_resp.headers = {"Set-Cookie": "DSID=xyz"}

        bypass_resp = MagicMock()
        bypass_resp.status_code = 200
        bypass_resp.text = '{"system": {"maintenance": "cloud-server-test"}}'

        session.get.side_effect = [fp_resp, bypass_resp]

        res = probe_ivanti(session, "https://ivanti.test", timeout=5)
        assert res.appliance == "ivanti"
        assert res.fingerprinted is True
        assert res.vulnerable is True

    def test_probe_citrix_vulnerable(self):
        session = MagicMock()
        vpn_resp = MagicMock()
        vpn_resp.status_code = 200
        vpn_resp.text = "<html><title>Citrix Gateway</title></html>"
        vpn_resp.headers = {"Set-Cookie": "NSC_TASS=123"}

        bleed_resp = MagicMock()
        bleed_resp.status_code = 200
        bleed_resp.text = '{"issuer": "https://citrix.test/oauth/idp", "openid-configuration": "leaked_memory_dump_' + ('x' * 1200) + '"}'

        session.get.side_effect = [vpn_resp, bleed_resp]

        res = probe_citrix(session, "https://citrix.test", timeout=5)
        assert res.appliance == "citrix"
        assert res.fingerprinted is True
        assert res.vulnerable is True

    def test_probe_fortinet_fingerprinted_never_sets_vulnerable(self):
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html>SSL-VPN Service -- Fortinet</html>"
        resp.headers = {"Set-Cookie": "SVPNCOOKIE=abc123; Path=/; Secure"}
        session.get.return_value = resp

        res = probe_fortinet(session, "https://forti-gateway.test", timeout=5)
        assert res.appliance == "fortinet"
        assert res.fingerprinted is True
        assert res.requires_manual_verification is True
        # Never actively tested, so never confirmed vulnerable either way.
        assert res.vulnerable is False
        assert "memory-corruption" in res.evidence_snippet

    def test_probe_fortinet_not_fingerprinted(self):
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "Not Found"
        resp.headers = {}
        session.get.return_value = resp

        res = probe_fortinet(session, "https://generic-gateway.test", timeout=5)
        assert res.appliance == "fortinet"
        assert res.fingerprinted is False
        assert res.requires_manual_verification is False

    @patch("tradecraft.adapters.perimeter_gateway_probe.execute.probe_checkpoint")
    @patch("tradecraft.adapters.perimeter_gateway_probe.execute.probe_paloalto")
    @patch("tradecraft.adapters.perimeter_gateway_probe.execute.probe_ivanti")
    @patch("tradecraft.adapters.perimeter_gateway_probe.execute.probe_citrix")
    @patch("tradecraft.adapters.perimeter_gateway_probe.execute.probe_fortinet")
    def test_execute_all_appliances(self, mock_forti, mock_citrix, mock_ivanti, mock_pa, mock_cp):
        mock_cp.return_value = ApplianceProbeResult(appliance="checkpoint", target_url="")
        mock_pa.return_value = ApplianceProbeResult(appliance="paloalto", target_url="")
        mock_ivanti.return_value = ApplianceProbeResult(appliance="ivanti", target_url="")
        mock_citrix.return_value = ApplianceProbeResult(appliance="citrix", target_url="")
        mock_forti.return_value = ApplianceProbeResult(appliance="fortinet", target_url="")

        res = execute("https://gateway.test", appliance="all")
        assert len(res.results) == 5
        assert mock_cp.called
        assert mock_pa.called
        assert mock_ivanti.called
        assert mock_citrix.called
        assert mock_forti.called

    @patch("tradecraft.adapters.perimeter_gateway_probe.execute.probe_checkpoint")
    def test_execute_single_appliance(self, mock_cp):
        mock_cp.return_value = ApplianceProbeResult(appliance="checkpoint", target_url="")
        res = execute("https://gateway.test", appliance="checkpoint")
        assert len(res.results) == 1
        assert res.results[0].appliance == "checkpoint"

    @patch("requests.Session")
    def test_execute_network_error(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.post.side_effect = requests.exceptions.ConnectionError("Connection timed out")
        mock_session.get.side_effect = requests.exceptions.ConnectionError("Connection timed out")

        res = execute("https://dead-gateway.test", appliance="checkpoint")
        assert len(res.results) == 1
        assert "timed out" in str(res.results[0].error)


class TestPerimeterGatewayParse:
    def test_parse_vulnerable_result(self):
        raw = RawPerimeterResult(
            target="vpn.example.com",
            base_url="https://vpn.example.com",
            results=[
                ApplianceProbeResult(
                    appliance="checkpoint",
                    target_url="https://vpn.example.com/clients/MyCRL",
                    fingerprinted=True,
                    vulnerable=True,
                    cve="CVE-2024-24919",
                    evidence_snippet="root:x:0:0:root:/root:/bin/bash",
                )
            ],
        )
        parsed = parse_perimeter_result(raw)
        assert parsed["vulnerable"] is True
        assert parsed["status"] == "vulnerable"
        assert len(parsed["vulnerable_appliances"]) == 1
        assert "CVE-2024-24919" in parsed["summary"]
        assert "sk182336" in parsed["recommendation"]

    def test_parse_safe_appliance_result(self):
        raw = RawPerimeterResult(
            target="vpn.example.com",
            base_url="https://vpn.example.com",
            results=[
                ApplianceProbeResult(
                    appliance="paloalto",
                    target_url="https://vpn.example.com/ssl-vpn/hipreport.esp",
                    fingerprinted=True,
                    vulnerable=False,
                    cve="CVE-2024-3400",
                    evidence_snippet="GlobalProtect active; hipreport returned 404",
                )
            ],
        )
        parsed = parse_perimeter_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "safe"
        assert len(parsed["detected_appliances"]) == 1
        assert "SAFE" in parsed["summary"]

    def test_parse_fortinet_exposure_is_not_conflated_with_safe(self):
        raw = RawPerimeterResult(
            target="vpn.example.com",
            base_url="https://vpn.example.com",
            results=[
                ApplianceProbeResult(
                    appliance="fortinet",
                    target_url="https://vpn.example.com/remote/login",
                    fingerprinted=True,
                    vulnerable=False,
                    requires_manual_verification=True,
                    cve="CVE-2022-42475, CVE-2023-27997, CVE-2024-21762",
                    evidence_snippet="Fortinet FortiGate SSL-VPN portal detected",
                )
            ],
        )
        parsed = parse_perimeter_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "exposed_unverified"
        assert "NOT TESTED" in parsed["summary"]
        assert "patch appears present" not in parsed["summary"]
        assert len(parsed["unverified_exposures"]) == 1
        assert parsed["unverified_exposures"][0]["appliance"] == "fortinet"

    def test_parse_vulnerable_takes_priority_over_unverified_exposure(self):
        raw = RawPerimeterResult(
            target="vpn.example.com",
            base_url="https://vpn.example.com",
            results=[
                ApplianceProbeResult(
                    appliance="citrix",
                    target_url="https://vpn.example.com/oauth/idp/.well-known/openid-configuration",
                    fingerprinted=True,
                    vulnerable=True,
                    cve="CVE-2023-4966",
                    evidence_snippet="CitrixBleed leaked buffer",
                ),
                ApplianceProbeResult(
                    appliance="fortinet",
                    target_url="https://vpn.example.com/remote/login",
                    fingerprinted=True,
                    requires_manual_verification=True,
                    cve="CVE-2022-42475",
                    evidence_snippet="Fortinet FortiGate SSL-VPN portal detected",
                ),
            ],
        )
        parsed = parse_perimeter_result(raw)
        assert parsed["status"] == "vulnerable"
        # Still surfaced, not dropped, alongside the confirmed finding.
        assert len(parsed["unverified_exposures"]) == 1
        assert parsed["unverified_exposures"][0]["appliance"] == "fortinet"

    def test_parse_not_applicable(self):
        raw = RawPerimeterResult(
            target="web.example.com",
            base_url="https://web.example.com",
            results=[
                ApplianceProbeResult(
                    appliance="checkpoint",
                    target_url="https://web.example.com/clients/MyCRL",
                    fingerprinted=False,
                    vulnerable=False,
                )
            ],
        )
        parsed = parse_perimeter_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "not_applicable"
        assert "NOT_APPLICABLE" in parsed["summary"]

    def test_parse_error(self):
        raw = RawPerimeterResult(target="vpn.example.com", error="target is required")
        parsed = parse_perimeter_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "error"
        assert parsed["error"] == "target is required"


class TestPerimeterGatewayTool:
    def test_registration(self):
        ids = [t.tool_id for t in ALL_TOOLS]
        assert "perimeter_gateway_probe" in ids

    def test_spec_attributes(self):
        tool = PerimeterGatewayProbe()
        assert tool.spec.name == "perimeter_gateway_probe"
        assert tool.required_binary is None
        assert tool.scope_param == "target"
        assert tool.destructive is False
        assert tool.is_available() is True
        assert "target" in tool.spec.parameters["properties"]
        assert "appliance" in tool.spec.parameters["properties"]

    @patch("tradecraft.adapters.perimeter_gateway_probe.execute.execute")
    def test_tool_run(self, mock_exec):
        mock_exec.return_value = RawPerimeterResult(
            target="vpn.example.com",
            base_url="https://vpn.example.com",
            results=[],
        )
        tool = PerimeterGatewayProbe()
        res = tool.run(target="vpn.example.com")
        assert res["target"] == "vpn.example.com"
        assert res["vulnerable"] is False

    def test_profile_membership(self):
        web = load_profile("web")
        cloud = load_profile("cloud")
        full = load_profile("full")
        assert "perimeter_gateway_probe" in web
        assert "perimeter_gateway_probe" in cloud
        assert "perimeter_gateway_probe" in full
