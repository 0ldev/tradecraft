"""Unit tests for nuclei adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.nuclei.execute import (
    RawNucleiResult,
    build_argv,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.nuclei.parse import (
    host_port_from_target,
    parse_nuclei_output,
    worst_severity,
)

MOCK_NUCLEI_JSONL = """
{"template":"http/technologies/php-detect.yaml","template-id":"php-detect","info":{"name":"PHP Detect","severity":"info","classification":{"cpe":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}},"type":"http","host":"example.com","port":"443","scheme":"https","url":"https://example.com","matched-at":"https://example.com","extracted-results":["5.6.40"]}
{"template":"http/cves/2021/CVE-2021-44228.yaml","template-id":"cve-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","classification":{"cve-id":["CVE-2021-44228"]}},"type":"http","host":"example.com","port":"443","scheme":"https","url":"https://example.com/api","matched-at":"https://example.com/api"}
{"template":"http/misconfiguration/cors.yaml","template-id":"cors-misconfig","info":{"name":"CORS Misconfiguration","severity":"medium"},"type":"http","host":"example.com","port":"443","scheme":"https","url":"https://example.com","matched-at":"https://example.com"}
{"corrupted json line
"""


class TestNucleiExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("example.com") == "https://example.com"
        assert normalize_target_url("http://example.com") == "http://example.com"
        assert normalize_target_url("https://example.com/test") == "https://example.com/test"
        assert normalize_target_url("example.com:80") == "http://example.com:80"
        assert normalize_target_url("example.com:443") == "https://example.com:443"
        assert normalize_target_url("") == ""

    def test_build_argv_default(self):
        argv = build_argv("https://example.com")
        assert argv == [
            "nuclei",
            "-target", "https://example.com",
            "-silent",
            "-jsonl",
            "-omit-raw",
            "-exclude-tags", "dos,fuzz",
            "-rl", "50",
            "-c", "10",
            "-timeout", "10",
            "-tags", "cve,misconfig,exposure,tech",
            "-severity", "low,medium,high,critical",
        ]

    def test_build_argv_with_template(self):
        argv = build_argv(
            "https://example.com",
            tags="cve",
            severity="critical",
            templates="cve-2021-44228",
            rate_limit=20,
            concurrency=5,
            timeout=5,
        )
        assert "-tags" in argv and argv[argv.index("-tags") + 1] == "cve"
        assert "-severity" in argv and argv[argv.index("-severity") + 1] == "critical"
        assert "-t" in argv and argv[argv.index("-t") + 1] == "cve-2021-44228"
        assert "-rl" in argv and argv[argv.index("-rl") + 1] == "20"
        assert "-c" in argv and argv[argv.index("-c") + 1] == "5"
        assert "-timeout" in argv and argv[argv.index("-timeout") + 1] == "5"

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "empty target"

    @patch("tradecraft.adapters.nuclei.execute.shutil.which", return_value=None)
    def test_execute_missing_binary(self, mock_which):
        res = execute("example.com")
        assert "nuclei binary not found" in (res.error or "")

    @patch("tradecraft.adapters.nuclei.execute.subprocess.run")
    def test_execute_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = MOCK_NUCLEI_JSONL
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = execute("https://example.com")
        assert res.error is None
        assert res.returncode == 0
        assert "cve-2021-44228" in res.stdout

    @patch("tradecraft.adapters.nuclei.execute.subprocess.run")
    def test_execute_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=180)
        res = execute("https://example.com")
        assert "nuclei timed out" in (res.error or "")


class TestNucleiParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("example.com") == ("example.com", 80)
        assert host_port_from_target("https://example.com") == ("example.com", 443)
        assert host_port_from_target("http://example.com:8080") == ("example.com", 8080)
        assert host_port_from_target("https://example.com:8443") == ("example.com", 8443)

    def test_worst_severity(self):
        assert worst_severity(["info", "low", "critical"]) == "critical"
        assert worst_severity(["info", "medium"]) == "medium"
        assert worst_severity(["info", "low"]) == "low"
        assert worst_severity([]) is None
        assert worst_severity(["unknown", ""]) is None

    def test_parse_real_captured_output(self):
        parsed = parse_nuclei_output(MOCK_NUCLEI_JSONL)
        assert parsed["total_findings"] == 3
        assert parsed["worst_severity"] == "critical"
        assert parsed["severities_count"]["critical"] == 1
        assert parsed["severities_count"]["medium"] == 1
        assert parsed["severities_count"]["info"] == 1

        first = parsed["findings"][0]
        assert first["template_id"] == "cve-2021-44228"
        assert first["severity"] == "critical"
        assert first["cve_id"] == ["CVE-2021-44228"]

        php = next(f for f in parsed["findings"] if f["template_id"] == "php-detect")
        assert php["extracted_results"] == ["5.6.40"]

    def test_parse_empty_and_noise_output(self):
        assert parse_nuclei_output("") == {
            "findings": [],
            "total_findings": 0,
            "worst_severity": None,
            "severities_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        noise = "random header\n[INF] scanning...\n{invalid json}\n"
        assert parse_nuclei_output(noise) == {
            "findings": [],
            "total_findings": 0,
            "worst_severity": None,
            "severities_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }


# Real line captured live from `nuclei -t
# http/misconfiguration/http-missing-security-headers.yaml` against
# exampleauto.com.br (2026-11-03). Confirmed root cause of a real,
# repeatedly-observed gap: three separate past engagements found missing
# security headers only via httpx_probe/manual inspection, never via
# nuclei -- because this template's real tag is "misconfig" (979 real
# templates use it), not "misconfiguration" (the old default, which only
# 7 outlier templates happen to use). The default tags string had a typo
# that silently excluded an entire valid tag class.
REAL_MISSING_HEADERS_LINE = (
    '{"template":"http/misconfiguration/http-missing-security-headers.yaml",'
    '"template-id":"http-missing-security-headers",'
    '"info":{"name":"HTTP Missing Security Headers",'
    '"tags":["misconfig","headers","generic","vuln"],'
    '"severity":"info","classification":{"cwe-id":["cwe-693"]}},'
    '"matcher-name":"cross-origin-opener-policy","type":"http",'
    '"host":"exampleauto.com.br","port":"443","scheme":"https",'
    '"url":"https://exampleauto.com.br","matched-at":"https://exampleauto.com.br"}'
)


class TestNucleiMisconfigTagFix:
    def test_default_tags_use_real_misconfig_tag_not_the_typo(self):
        """Regression test for the typo itself: the default must be the
        tag nuclei's own templates actually use."""
        argv = build_argv("https://example.com")
        tags_value = argv[argv.index("-tags") + 1]
        assert "misconfig" in tags_value.split(",")
        assert "misconfiguration" not in tags_value.split(",")

    def test_parses_real_captured_missing_security_headers_line(self):
        """The parser side was never the problem -- it already handles
        info-severity findings correctly. This confirms that: once nuclei
        actually runs the template (the argv fix above), parse_nuclei_output
        surfaces it like any other finding."""
        parsed = parse_nuclei_output(REAL_MISSING_HEADERS_LINE)
        assert parsed["total_findings"] == 1
        finding = parsed["findings"][0]
        assert finding["template_id"] == "http-missing-security-headers"
        assert finding["severity"] == "info"
        assert finding["matched_at"] == "https://exampleauto.com.br"
