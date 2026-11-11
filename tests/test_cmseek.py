"""
Unit tests for CMSeeK adapter (execute, parse) and Tool glue.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from tradecraft.adapters.cmseek.execute import (
    CMSEEK_SCRIPT_DEFAULT,
    RawCMSeeKResult,
    build_argv,
    extract_host_from_target,
    find_script,
    normalize_target_url,
)
from tradecraft.adapters.cmseek.parse import (
    host_port_from_target,
    parse_cmseek_output,
)
from tradecraft.tools.cmseek import CMSeeK
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS

REAL_CAPTURED_WP_JSON = {
    "cms_id": "wp",
    "cms_name": "WordPress",
    "cms_url": "https://wordpress.org",
    "detection_param": "header",
    "last_scanned": "2026-11-07 16:09:03.901051",
    "url": "https://wordpress.org",
    "user_registration": "https://wordpress.org/wp-login.php?action=register",
    "wp_plugins": "gutenberg Version 24.3.1,",
    "wp_themes": "wporg-main-2022 Version 1785161844,wporg-parent-2021 Version 1781196442,",
    "wp_users": "annezazu,wordpressdotorg,adamwood,poliuk,joen,gomp,ryelle,zieladam,debdesign,",
    "wp_version": "7.2-beta4-65325",
}

REAL_CAPTURED_WP_STDOUT = """
[i] Scanning Site: https://wordpress.org
[*] CMS Detected, CMS ID: wp, Detection method: header
[*] Version Detected, WordPress Version 7.2-beta4-65325
[i] Checking user registration status
[*] User registration open: https://wordpress.org/wp-login.php?action=register
[*] 1 Plugin enumerated!
[*] 2 themes detected!
[*] Found user from wp-json : annezazu
[*] Found user from wp-json : adamwood
"""


class TestCMSeeKExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("example.com") == "https://example.com"
        assert normalize_target_url("http://example.com") == "http://example.com"
        assert normalize_target_url("  https://sub.domain.org/path  ") == "https://sub.domain.org/path"
        assert normalize_target_url("") == ""

    def test_extract_host_from_target(self):
        assert extract_host_from_target("https://example.com/test") == "example.com"
        assert extract_host_from_target("http://192.168.1.1:8080/app") == "192.168.1.1"

    def test_build_argv(self):
        argv = build_argv("https://target.com")
        assert argv == ["python3", CMSEEK_SCRIPT_DEFAULT, "-u", "https://target.com", "--batch", "--follow-redirect"]

        argv_light = build_argv("https://target.com", follow_redirect=False, light_scan=True, only_cms=True)
        assert argv_light == ["python3", CMSEEK_SCRIPT_DEFAULT, "-u", "https://target.com", "--batch", "--light-scan", "-o"]

    @patch("os.path.isfile")
    def test_find_script(self, mock_isfile):
        mock_isfile.return_value = True
        assert find_script() == CMSEEK_SCRIPT_DEFAULT


class TestCMSeeKParse:
    def test_host_port_from_target(self):
        host, port = host_port_from_target("https://blog.example.com/wp")
        assert host == "blog.example.com"
        assert port == 443

        host, port = host_port_from_target("http://10.0.0.1:8080/test")
        assert host == "10.0.0.1"
        assert port == 8080

    def test_parse_real_captured_json(self):
        raw = RawCMSeeKResult(
            stdout=REAL_CAPTURED_WP_STDOUT,
            target_url="https://wordpress.org",
            json_data=REAL_CAPTURED_WP_JSON,
        )
        parsed = parse_cmseek_output(raw)
        assert parsed["cms_detected"] is True
        assert parsed["cms_id"] == "wp"
        assert parsed["cms_name"] == "WordPress"
        assert parsed["cms_version"] == "7.2-beta4-65325"
        assert parsed["detection_method"] == "header"
        assert "gutenberg Version 24.3.1" in parsed["plugins"]
        assert "annezazu" in parsed["users"]
        assert len(parsed["users"]) == 9

    def test_parse_stdout_fallback(self):
        raw = RawCMSeeKResult(
            stdout=REAL_CAPTURED_WP_STDOUT,
            target_url="https://wordpress.org",
            json_data={},
        )
        parsed = parse_cmseek_output(raw)
        assert parsed["cms_detected"] is True
        assert parsed["cms_id"] == "wp"
        assert parsed["cms_version"] == "7.2-beta4-65325"
        assert parsed["detection_method"] == "header"
        assert "annezazu" in parsed["users"]

    def test_parse_not_detected(self):
        raw = RawCMSeeKResult(
            stdout="[x] CMS Detection failed\n",
            target_url="https://noncms.com",
            json_data={},
        )
        parsed = parse_cmseek_output(raw)
        assert parsed["cms_detected"] is False
        assert parsed["cms_id"] == ""
        assert parsed["cms_version"] == ""
        assert parsed["plugins"] == []
        assert parsed["users"] == []

    def test_parse_error(self):
        raw = RawCMSeeKResult(
            error="cmseek execution timed out after 180s",
            target_url="https://timeout.com",
        )
        parsed = parse_cmseek_output(raw)
        assert parsed["cms_detected"] is False
        assert parsed["error"] == "cmseek execution timed out after 180s"


class TestCMSeeKTool:
    @patch("tradecraft.tools.cmseek.cmseek_execute.find_script", return_value="/opt/cmseek/cmseek.py")
    @patch("shutil.which", return_value="/usr/bin/python3")
    def test_is_available(self, mock_which, mock_find):
        tool = CMSeeK()
        assert tool.is_available() is True

    @patch("tradecraft.tools.cmseek.cmseek_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawCMSeeKResult(error="cmseek script not found", target_url="https://example.com")
        tool = CMSeeK()
        res = tool.run(target="https://example.com")
        assert res["cms_detected"] is False
        assert res["error"] == "cmseek script not found"

    @patch("tradecraft.tools.cmseek.cmseek_execute.execute")
    def test_run_success_and_facts_evidence(self, mock_exec):
        mock_exec.return_value = RawCMSeeKResult(
            stdout=REAL_CAPTURED_WP_STDOUT,
            target_url="https://wordpress.org",
            json_data=REAL_CAPTURED_WP_JSON,
        )
        tool = CMSeeK()
        res = tool.run(target="https://wordpress.org")

        assert res["cms_detected"] is True
        assert res["cms_name"] == "WordPress"
        assert res["cms_version"] == "7.2-beta4-65325"
        assert "_full_evidence" in res

        evidence = tool.extract_evidence({"target": "https://wordpress.org"}, res)
        assert evidence is not None
        canonical, full = evidence
        assert canonical == "wordpress.org"
        assert full["json_data"]["cms_id"] == "wp"

        # Fact extraction
        facts = tool.extract_facts({"target": "https://wordpress.org"}, res)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "wordpress.org"
        assert fact["port"] == 443
        assert fact["cms_detected"] is True
        assert fact["cms_id"] == "wp"
        assert fact["cms_version"] == "7.2-beta4-65325"
        assert "annezazu" in fact["harvested_usernames"]

    def test_registry_and_profile_membership(self):
        tool_ids = [t.tool_id for t in ALL_TOOLS]
        assert "cmseek" in tool_ids

        web_profile = load_profile("web")
        assert "cmseek" in web_profile

        full_profile = load_profile("full")
        assert "cmseek" in full_profile
