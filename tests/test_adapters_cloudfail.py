"""Unit tests for cloudfail adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.cloudfail.execute import (
    RawCloudfailResult,
    build_argv,
    execute,
    normalize_target,
)
from tradecraft.adapters.cloudfail.parse import parse_cloudfail_output

REAL_CAPTURED_CLOUDFLARE_OUTPUT = r"""
   ____ _                 _ _____     _ _
  / ___| | ___  _   _  __| |  ___|_ _(_) |
 | |   | |/ _ \| | | |/ _` | |_ / _` | | |
 | |___| | (_) | |_| | (_| |  _| (_| | | |
  \____|_|\___/ \__,_|\__,_|_|  \__,_|_|_|
    v1.0.5                      by m0rtem


[21:20:28] Initializing CloudFail - the date is: 01/11/2026  
[21:20:28] Fetching initial information from: exampleauto.com.br...  
[21:20:28] Server IP: 104.26.8.9  
[21:20:28] Testing if exampleauto.com.br is on the Cloudflare network...  
[21:20:28] exampleauto.com.br is part of the Cloudflare network!  
[21:20:28] Testing for misconfigured DNS using dnsdumpster...  
[21:20:28] DNSDumpster query failed: list index out of range  
[21:20:28] Scanning crimeflare database...  
[21:20:28] [FOUND:IP] 203.0.113.69  
[21:20:28] Scanning 11219 subdomains (subdomains_top100.txt), please wait...  
[21:20:31] [FOUND:SUBDOMAIN] portal.exampleauto.com.br ON CLOUDFLARE NETWORK!  
[21:20:31] [FOUND:SUBDOMAIN] api.exampleauto.com.br ON CLOUDFLARE NETWORK!  
[21:20:41] [FOUND:SUBDOMAIN] status.exampleauto.com.br ON CLOUDFLARE NETWORK!  
[21:20:43] [FOUND:SUBDOMAIN] sso.exampleauto.com.br ON CLOUDFLARE NETWORK!  
[21:20:47] Scanning finished, we did not find anything, sorry...  
"""

REAL_CAPTURED_DIRECT_OUTPUT = r"""
   ____ _                 _ _____     _ _
  / ___| | ___  _   _  __| |  ___|_ _(_) |
 | |   | |/ _ \| | | |/ _` | |_ / _` | | |
 | |___| | (_) | |_| | (_| |  _| (_| | | |
  \____|_|\___/ \__,_|\__,_|_|  \__,_|_|_|
    v1.0.5                      by m0rtem


[21:20:57] Initializing CloudFail - the date is: 01/11/2026  
[21:20:57] Fetching initial information from: examplepaint.com.br...  
[21:20:57] Server IP: 192.0.2.10  
[21:20:57] Testing if examplepaint.com.br is on the Cloudflare network...  
[21:20:57] examplepaint.com.br is not part of the Cloudflare network, quitting...  
"""

CAPTURED_WITH_UNMASKED_SUBDOMAINS_AND_HOSTS = """
[21:20:28] Initializing CloudFail - the date is: 01/11/2026  
[21:20:28] Server IP: 104.26.8.9  
[21:20:28] exampleauto.com.br is part of the Cloudflare network!  
[FOUND:HOST] direct.exampleauto.com.br 198.51.100.1 AS13335 Locaweb Brazil
[FOUND:DNS] ns1.exampleauto.com.br 198.51.100.2 AS13335 Locaweb Brazil
[FOUND:IP] 203.0.113.69
[FOUND:SUBDOMAIN] origin.exampleauto.com.br IP: 198.51.100.3 HTTP: 200
[FOUND:SUBDOMAIN] portal.exampleauto.com.br ON CLOUDFLARE NETWORK!
"""


class TestCloudfailExecute:
    def test_normalize_target(self):
        assert normalize_target("https://example.com/login") == "example.com"
        assert normalize_target("http://sub.example.com:8080/path") == "sub.example.com"
        assert normalize_target("example.com") == "example.com"
        assert normalize_target("") == ""

    def test_build_argv_default(self):
        argv = build_argv("example.com")
        assert argv == ["cloudfail", "-t", "example.com", "-s", "subdomains_top100.txt"]

    def test_build_argv_custom_subdomains(self):
        argv = build_argv("https://target.com", subdomains="custom.txt")
        assert argv == ["cloudfail", "-t", "target.com", "-s", "custom.txt"]

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "empty target domain"

    @patch("tradecraft.adapters.cloudfail.execute.shutil.which", return_value=None)
    def test_execute_missing_binary(self, mock_which):
        res = execute("example.com")
        assert "cloudfail binary not found" in (res.error or "")

    @patch("tradecraft.adapters.cloudfail.execute.shutil.which", return_value="/usr/bin/cloudfail")
    @patch("tradecraft.adapters.cloudfail.execute.subprocess.run")
    def test_execute_success(self, mock_run, mock_which):
        mock_proc = MagicMock()
        mock_proc.stdout = REAL_CAPTURED_CLOUDFLARE_OUTPUT
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = execute("exampleauto.com.br")
        assert res.error is None
        assert res.returncode == 0
        assert "exampleauto.com.br is part of the Cloudflare network" in res.stdout

    @patch("tradecraft.adapters.cloudfail.execute.shutil.which", return_value="/usr/bin/cloudfail")
    @patch("tradecraft.adapters.cloudfail.execute.subprocess.run")
    def test_execute_timeout(self, mock_run, mock_which):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["cloudfail"], timeout=60)
        res = execute("example.com", timeout=60)
        assert "cloudfail timed out after 60s" in (res.error or "")


class TestCloudfailParse:
    def test_parse_empty(self):
        parsed = parse_cloudfail_output("", target="example.com")
        assert parsed["target"] == "example.com"
        assert parsed["is_cloudflare"] is False
        assert parsed["origin_unmasked"] is False
        assert parsed["unmasked_origin_ips"] == []

    def test_parse_real_captured_direct_host(self):
        parsed = parse_cloudfail_output(REAL_CAPTURED_DIRECT_OUTPUT, target="examplepaint.com.br")
        assert parsed["target"] == "examplepaint.com.br"
        assert parsed["server_ip"] == "192.0.2.10"
        assert parsed["is_cloudflare"] is False
        assert parsed["origin_unmasked"] is False
        assert parsed["unmasked_origin_ips"] == []
        assert parsed["cloudflare_subdomains"] == []

    def test_parse_real_captured_cloudflare_host(self):
        parsed = parse_cloudfail_output(REAL_CAPTURED_CLOUDFLARE_OUTPUT, target="exampleauto.com.br")
        assert parsed["target"] == "exampleauto.com.br"
        assert parsed["server_ip"] == "104.26.8.9"
        assert parsed["is_cloudflare"] is True
        assert parsed["origin_unmasked"] is True
        assert parsed["unmasked_origin_ips"] == ["203.0.113.69"]
        assert "portal.exampleauto.com.br" in parsed["cloudflare_subdomains"]
        assert "api.exampleauto.com.br" in parsed["cloudflare_subdomains"]
        assert "status.exampleauto.com.br" in parsed["cloudflare_subdomains"]
        assert "sso.exampleauto.com.br" in parsed["cloudflare_subdomains"]

    def test_parse_unmasked_subdomains_and_hosts(self):
        parsed = parse_cloudfail_output(CAPTURED_WITH_UNMASKED_SUBDOMAINS_AND_HOSTS, target="exampleauto.com.br")
        assert parsed["is_cloudflare"] is True
        assert parsed["origin_unmasked"] is True
        # Crimeflare IP, Host IP, Subdomain IP
        assert "203.0.113.69" in parsed["unmasked_origin_ips"]
        assert "198.51.100.1" in parsed["unmasked_origin_ips"]
        assert "198.51.100.3" in parsed["unmasked_origin_ips"]
        assert len(parsed["unmasked_subdomains"]) == 1
        assert parsed["unmasked_subdomains"][0]["subdomain"] == "origin.exampleauto.com.br"
        assert parsed["unmasked_subdomains"][0]["ip"] == "198.51.100.3"
        assert parsed["unmasked_subdomains"][0]["status_code"] == 200
        assert len(parsed["dnsdumpster_hosts"]) == 2
