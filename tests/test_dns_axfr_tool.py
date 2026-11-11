"""
Unit tests for the DnsAxfr Tool glue (run, extract_evidence, extract_facts).
"""
import unittest
from unittest import mock

from tradecraft.adapters.dns_axfr.execute import RawAxfrResult
from tradecraft.tools.dns_axfr import DnsAxfr


class TestDnsAxfrTool(unittest.TestCase):
    def setUp(self):
        self.tool = DnsAxfr()

    @mock.patch("tradecraft.adapters.dns_axfr.execute.execute")
    def test_run_empty_nameservers(self, mock_exec):
        mock_exec.return_value = {}
        res = self.tool.run("unresolvable.invalid")
        self.assertFalse(res["vulnerable"])
        self.assertEqual(res["nameservers_tested"], [])
        self.assertIn("no nameservers resolved", res["note"])

    @mock.patch("tradecraft.adapters.dns_axfr.execute.execute")
    def test_run_not_vulnerable(self, mock_exec):
        mock_exec.return_value = {
            "ns1.examplehost.net": RawAxfrResult(
                "ns1.examplehost.net", "; Transfer failed.\n", "", 0
            )
        }
        res = self.tool.run("examplepaint.com.br")
        self.assertEqual(res["target"], "examplepaint.com.br")
        self.assertFalse(res["vulnerable"])
        self.assertEqual(res["vulnerable_nameservers"], [])
        self.assertIn("_full_evidence", res)

    @mock.patch("tradecraft.adapters.dns_axfr.execute.execute")
    def test_run_vulnerable(self, mock_exec):
        zone_data = "target.com. 3600 IN A 1.2.3.4\n"
        mock_exec.return_value = {
            "ns1.vuln.com": RawAxfrResult("ns1.vuln.com", zone_data, "", 0)
        }
        res = self.tool.run("target.com")
        self.assertEqual(res["target"], "target.com")
        self.assertTrue(res["vulnerable"])
        self.assertEqual(res["vulnerable_nameservers"], ["ns1.vuln.com"])
        self.assertIn("_full_evidence", res)

    def test_extract_evidence(self):
        result = {
            "target": "target.com",
            "vulnerable": True,
            "_full_evidence": {"target": "target.com", "raw": {"ns1": "data"}},
        }
        extracted = self.tool.extract_evidence({"target": "target.com"}, result)
        self.assertIsNotNone(extracted)
        target, evidence = extracted
        self.assertEqual(target, "target.com")
        self.assertEqual(evidence["raw"]["ns1"], "data")
        self.assertNotIn("_full_evidence", result)

    def test_extract_facts_when_not_vulnerable(self):
        result = {"target": "target.com", "vulnerable": False}
        facts = self.tool.extract_facts({"target": "target.com"}, result)
        self.assertEqual(facts, [])

    def test_extract_facts_when_vulnerable(self):
        result = {
            "target": "target.com",
            "vulnerable": True,
            "vulnerable_nameservers": ["ns1.vuln.com"],
            "evidence_id": "dns_axfr:target.com",
        }
        facts = self.tool.extract_facts({"target": "target.com"}, result)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["host"], "target.com")
        self.assertEqual(facts[0]["port"], 53)
        self.assertEqual(facts[0]["dns_zone_transfer"], "vulnerable via ns1.vuln.com")
        self.assertEqual(facts[0]["evidence"], "dns_axfr:target.com")


if __name__ == "__main__":
    unittest.main()
