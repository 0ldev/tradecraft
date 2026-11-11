"""
Unit tests for the RetireJs Tool glue (run, extract_evidence, extract_facts).
"""
import unittest
from unittest import mock

from tradecraft.adapters.retire_js.execute import RawRetireResult
from tradecraft.tools.retire_js import RetireJs

REAL_RETIRE_VULNERABLE_JSON = """{
  "version": "6.1.0",
  "data": [
    {
      "file": "/tmp/test/jquery.js",
      "results": [
        {
          "version": "1.6.1",
          "component": "jquery",
          "npmname": "jquery",
          "detection": "filecontent",
          "vulnerabilities": [
            {
              "severity": "medium",
              "identifiers": {
                "summary": "XSS with location.hash",
                "CVE": ["CVE-2011-4969"],
                "githubID": "GHSA-579v-mp3v-rrw5"
              },
              "cwe": ["CWE-79"]
            }
          ]
        }
      ]
    }
  ]
}"""


class TestRetireJsTool(unittest.TestCase):
    def setUp(self):
        self.tool = RetireJs()

    @mock.patch("tradecraft.adapters.retire_js.execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawRetireResult("", "error", 1, 0, error="retire failed")
        res = self.tool.run("https://example.com")
        self.assertFalse(res["vulnerable"])
        self.assertEqual(res["error"], "retire failed")

    @mock.patch("tradecraft.adapters.retire_js.execute.execute")
    def test_run_clean(self, mock_exec):
        mock_exec.return_value = RawRetireResult('{"data": []}', "", 0, 2)
        res = self.tool.run("https://example.com")
        self.assertFalse(res["vulnerable"])
        self.assertEqual(res["vulnerable_components"], [])
        self.assertEqual(res["scripts_downloaded"], 2)
        self.assertIn("_full_evidence", res)

    @mock.patch("tradecraft.adapters.retire_js.execute.execute")
    def test_run_vulnerable(self, mock_exec):
        mock_exec.return_value = RawRetireResult(REAL_RETIRE_VULNERABLE_JSON, "", 0, 1)
        res = self.tool.run("https://example.com")
        self.assertTrue(res["vulnerable"])
        self.assertEqual(len(res["vulnerable_components"]), 1)
        self.assertEqual(res["summary"], ["jquery@1.6.1"])
        self.assertIn("_full_evidence", res)

    def test_extract_evidence(self):
        result = {
            "target": "https://example.com",
            "vulnerable": True,
            "_full_evidence": {"target": "https://example.com", "raw": "{}"},
        }
        extracted = self.tool.extract_evidence({"target": "https://example.com"}, result)
        self.assertIsNotNone(extracted)
        target, evidence = extracted
        self.assertEqual(target, "example.com")
        self.assertEqual(evidence["target"], "https://example.com")
        self.assertNotIn("_full_evidence", result)

    def test_extract_facts_when_not_vulnerable(self):
        result = {"target": "https://example.com", "vulnerable": False, "vulnerable_components": []}
        facts = self.tool.extract_facts({"target": "https://example.com"}, result)
        self.assertEqual(facts, [])

    def test_extract_facts_when_vulnerable(self):
        result = {
            "target": "https://example.com",
            "vulnerable": True,
            "evidence_id": "retire_js:example.com",
            "vulnerable_components": [
                {
                    "component": "jquery",
                    "version": "1.6.1",
                }
            ],
        }
        facts = self.tool.extract_facts({"target": "https://example.com"}, result)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["host"], "example.com")
        self.assertEqual(facts[0]["port"], 443)
        self.assertEqual(facts[0]["vulnerable_js_library"], "jquery@1.6.1")
        self.assertEqual(facts[0]["evidence"], "retire_js:example.com")


if __name__ == "__main__":
    unittest.main()
