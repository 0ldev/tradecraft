"""
Unit tests for the dns_axfr adapter (execute and parse).
"""
import subprocess
import unittest
from unittest import mock

from tradecraft.adapters.dns_axfr import execute as dns_axfr_execute
from tradecraft.adapters.dns_axfr import parse as dns_axfr_parse
from tradecraft.adapters.dns_axfr.execute import RawAxfrResult

REAL_TRANSFER_FAILED_OUTPUT = """; <<>> DiG 9.18.28 <<>> axfr examplepaint.com.br @ns1.examplehost.net +time=5 +tries=1
;; global options: +cmd
; Transfer failed.
"""

REAL_CONNECTION_REFUSED_OUTPUT = """; <<>> DiG 9.18.28 <<>> axfr example.com @10.0.0.1 +time=5 +tries=1
;; communications error to 10.0.0.1#53: connection refused
"""

REAL_SUCCESSFUL_ZONE_TRANSFER_OUTPUT = """; <<>> DiG 9.18.28 <<>> axfr zonetransfer.me @nsztm1.digi.ninja +time=5 +tries=1
;; global options: +cmd
zonetransfer.me.	7200	IN	SOA	nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
zonetransfer.me.	300	IN	HINFO	"Casio fx-7000G" "Windows 95"
zonetransfer.me.	301	IN	TXT	"google-site-verification=abc"
zonetransfer.me.	7200	IN	MX	0 ASPMX.L.GOOGLE.COM.
zonetransfer.me.	7200	IN	A	13.248.157.195
zonetransfer.me.	7200	IN	SOA	nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
;; Query time: 100 msec
;; SERVER: 13.248.157.195#53(nsztm1.digi.ninja)
;; WHEN: Mon Nov 02 00:00:00 UTC 2026
;; XFR size: 6 records (messages 1, bytes 450)
"""


class TestDnsAxfrExecute(unittest.TestCase):
    @mock.patch("subprocess.run")
    def test_resolve_nameservers_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ns1.examplehost.net.\nns2.examplehost.net.\nns1.examplehost.net.\n", stderr=""
        )
        ns = dns_axfr_execute.resolve_nameservers("examplepaint.com.br")
        self.assertEqual(ns, ["ns1.examplehost.net", "ns2.examplehost.net"])
        mock_run.assert_called_once_with(
            ["dig", "NS", "examplepaint.com.br", "+short"],
            text=True, capture_output=True, timeout=10, stdin=subprocess.DEVNULL,
        )

    @mock.patch("subprocess.run")
    def test_resolve_nameservers_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error")
        ns = dns_axfr_execute.resolve_nameservers("nonexistent.invalid")
        self.assertEqual(ns, [])

    @mock.patch("subprocess.run")
    def test_resolve_nameservers_empty_target(self, mock_run):
        ns = dns_axfr_execute.resolve_nameservers("")
        self.assertEqual(ns, [])
        mock_run.assert_not_called()

    @mock.patch("subprocess.run")
    def test_attempt_transfer_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=REAL_TRANSFER_FAILED_OUTPUT, stderr=""
        )
        res = dns_axfr_execute.attempt_transfer("examplepaint.com.br", "ns1.examplehost.net")
        self.assertEqual(res.nameserver, "ns1.examplehost.net")
        self.assertEqual(res.stdout, REAL_TRANSFER_FAILED_OUTPUT)
        self.assertIsNone(res.error)

    @mock.patch("subprocess.run")
    def test_attempt_transfer_missing_binary(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        res = dns_axfr_execute.attempt_transfer("examplepaint.com.br", "ns1.examplehost.net")
        self.assertEqual(res.error, "dig executable not found")

    @mock.patch("subprocess.run")
    def test_attempt_transfer_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="dig", timeout=5)
        res = dns_axfr_execute.attempt_transfer("examplepaint.com.br", "ns1.examplehost.net", timeout=5)
        self.assertEqual(res.error, "dig timed out after 5s")

    @mock.patch("tradecraft.adapters.dns_axfr.execute.resolve_nameservers")
    @mock.patch("tradecraft.adapters.dns_axfr.execute.attempt_transfer")
    def test_execute_orchestrates_per_nameserver(self, mock_attempt, mock_resolve):
        mock_resolve.return_value = ["ns1.example.com", "ns2.example.com"]
        mock_attempt.side_effect = [
            RawAxfrResult("ns1.example.com", "out1", "", 0),
            RawAxfrResult("ns2.example.com", "out2", "", 0),
        ]
        results = dns_axfr_execute.execute("example.com")
        self.assertEqual(len(results), 2)
        self.assertIn("ns1.example.com", results)
        self.assertIn("ns2.example.com", results)


class TestDnsAxfrParse(unittest.TestCase):
    def test_parse_one_transfer_failed(self):
        raw = RawAxfrResult("ns1.examplehost.net", REAL_TRANSFER_FAILED_OUTPUT, "", 0)
        parsed = dns_axfr_parse.parse_one(raw)
        self.assertEqual(parsed["nameserver"], "ns1.examplehost.net")
        self.assertFalse(parsed["vulnerable"])
        self.assertEqual(parsed["record_count"], 0)
        self.assertEqual(parsed["sample_records"], [])

    def test_parse_one_connection_refused(self):
        raw = RawAxfrResult("10.0.0.1", REAL_CONNECTION_REFUSED_OUTPUT, "", 1)
        parsed = dns_axfr_parse.parse_one(raw)
        self.assertFalse(parsed["vulnerable"])

    def test_parse_one_vulnerable_success(self):
        raw = RawAxfrResult("nsztm1.digi.ninja", REAL_SUCCESSFUL_ZONE_TRANSFER_OUTPUT, "", 0)
        parsed = dns_axfr_parse.parse_one(raw)
        self.assertEqual(parsed["nameserver"], "nsztm1.digi.ninja")
        self.assertTrue(parsed["vulnerable"])
        self.assertEqual(parsed["record_count"], 6)
        self.assertEqual(len(parsed["sample_records"]), 6)
        self.assertIn("zonetransfer.me.\t7200\tIN\tA\t13.248.157.195", parsed["sample_records"])

    def test_parse_all_mixed_results(self):
        raw = {
            "ns1.safe.com": RawAxfrResult("ns1.safe.com", REAL_TRANSFER_FAILED_OUTPUT, "", 0),
            "ns2.vuln.com": RawAxfrResult("ns2.vuln.com", REAL_SUCCESSFUL_ZONE_TRANSFER_OUTPUT, "", 0),
        }
        all_parsed = dns_axfr_parse.parse_all(raw)
        self.assertEqual(all_parsed["nameservers_tested"], ["ns1.safe.com", "ns2.vuln.com"])
        self.assertEqual(all_parsed["vulnerable_nameservers"], ["ns2.vuln.com"])
        self.assertFalse(all_parsed["results"]["ns1.safe.com"]["vulnerable"])
        self.assertTrue(all_parsed["results"]["ns2.vuln.com"]["vulnerable"])


if __name__ == "__main__":
    unittest.main()
