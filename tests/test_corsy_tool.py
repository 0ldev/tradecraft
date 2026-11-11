"""
Unit tests for the Corsy Tool glue (run, extract_evidence, extract_facts).
"""
import unittest
from unittest import mock

from tradecraft.adapters.corsy.execute import RawCorsyResult
from tradecraft.tools.corsy import Corsy

REAL_CORSY_MISCONFIG_JSON = """{
    "https://example.com/api/user": {
        "class": "Reflected Origin",
        "description": "The origin header is reflected in Access-Control-Allow-Origin header.",
        "severity": "High",
        "exploitation": "An attacker can make authenticated requests to this endpoint.",
        "acao header": "https://attacker.com",
        "acac header": "true"
    }
}"""


class TestCorsyTool(unittest.TestCase):
    def setUp(self):
        self.tool = Corsy()

    @mock.patch("tradecraft.adapters.corsy.execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawCorsyResult("https://example.com", "", "error", 1, error="corsy error")
        res = self.tool.run("https://example.com")
        self.assertFalse(res["misconfigured"])
        self.assertEqual(res["error"], "corsy error")

    @mock.patch("tradecraft.adapters.corsy.execute.execute")
    def test_run_clean(self, mock_exec):
        mock_exec.return_value = RawCorsyResult("https://example.com", "", "", 0)
        res = self.tool.run("https://example.com")
        self.assertFalse(res["misconfigured"])
        self.assertEqual(res["findings"], [])
        self.assertIn("_full_evidence", res)

    @mock.patch("tradecraft.adapters.corsy.execute.execute")
    def test_run_misconfigured(self, mock_exec):
        mock_exec.return_value = RawCorsyResult("https://example.com/api/user", REAL_CORSY_MISCONFIG_JSON, "", 0)
        res = self.tool.run("https://example.com/api/user")
        self.assertTrue(res["misconfigured"])
        self.assertEqual(len(res["findings"]), 1)
        self.assertIn("_full_evidence", res)

    def test_extract_evidence(self):
        result = {
            "url": "https://example.com/api/user",
            "misconfigured": True,
            "_full_evidence": {"url": "https://example.com/api/user", "raw": "{}"},
        }
        extracted = self.tool.extract_evidence({"url": "https://example.com/api/user"}, result)
        self.assertIsNotNone(extracted)
        target, evidence = extracted
        self.assertEqual(target, "example.com")
        self.assertEqual(evidence["url"], "https://example.com/api/user")
        self.assertNotIn("_full_evidence", result)

    def test_extract_facts_when_not_misconfigured(self):
        result = {"url": "https://example.com", "misconfigured": False, "findings": []}
        facts = self.tool.extract_facts({"url": "https://example.com"}, result)
        self.assertEqual(facts, [])

    def test_extract_facts_when_misconfigured(self):
        result = {
            "url": "https://example.com/api/user",
            "misconfigured": True,
            "evidence_id": "corsy:example.com",
            "findings": [
                {
                    "url": "https://example.com/api/user",
                    "class": "Reflected Origin",
                    "description": "Reflected Origin",
                }
            ],
        }
        facts = self.tool.extract_facts({"url": "https://example.com/api/user"}, result)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["host"], "example.com")
        self.assertEqual(facts[0]["port"], 443)
        self.assertEqual(facts[0]["cors_misconfig"], "Reflected Origin (https://example.com/api/user)")
        self.assertEqual(facts[0]["evidence"], "corsy:example.com")


if __name__ == "__main__":
    unittest.main()
