"""
Unit tests for the corsy adapter (execute and parse).
"""
import json
import subprocess
import unittest
from unittest import mock

from tradecraft.adapters.corsy import execute as corsy_execute
from tradecraft.adapters.corsy import parse as corsy_parse

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


class TestCorsyExecute(unittest.TestCase):
    def test_build_argv_basic(self):
        argv = corsy_execute.build_argv("https://example.com/api", "/tmp/out.json")
        self.assertEqual(argv, ["corsy", "-u", "https://example.com/api", "-o", "/tmp/out.json"])

    def test_build_argv_with_headers(self):
        headers = "Cookie: session=xyz\nAuthorization: Bearer token123"
        argv = corsy_execute.build_argv("https://example.com/api", "/tmp/out.json", headers=headers)
        self.assertEqual(argv[:4], ["corsy", "-u", "https://example.com/api", "-o"])
        self.assertEqual(argv[4], "/tmp/out.json")
        self.assertEqual(argv[5], "--headers")
        header_dict = json.loads(argv[6])
        self.assertEqual(header_dict, {"Cookie": "session=xyz", "Authorization": "Bearer token123"})

    def test_execute_empty_url(self):
        res = corsy_execute.execute("")
        self.assertEqual(res.error, "empty url")
        self.assertEqual(res.returncode, 1)

    @mock.patch("subprocess.run")
    def test_execute_missing_binary(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        res = corsy_execute.execute("https://example.com")
        self.assertEqual(res.error, "corsy executable not found")

    @mock.patch("subprocess.run")
    def test_execute_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="corsy", timeout=30)
        res = corsy_execute.execute("https://example.com", timeout=30)
        self.assertEqual(res.error, "corsy timed out after 30s")

    @mock.patch("subprocess.run")
    def test_execute_success_reads_temp_file(self, mock_run):
        def fake_run(argv, **kwargs):
            out_path = argv[argv.index("-o") + 1]
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(REAL_CORSY_MISCONFIG_JSON)
            return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run
        res = corsy_execute.execute("https://example.com/api/user")
        self.assertIsNone(res.error)
        self.assertEqual(res.stdout, REAL_CORSY_MISCONFIG_JSON)


class TestCorsyParse(unittest.TestCase):
    def test_parse_empty_output(self):
        res = corsy_parse.parse_corsy_output("", default_url="https://example.com")
        self.assertFalse(res["misconfigured"])
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["url"], "https://example.com")

    def test_parse_invalid_json(self):
        res = corsy_parse.parse_corsy_output("Not JSON")
        self.assertFalse(res["misconfigured"])
        self.assertEqual(res["findings"], [])

    def test_parse_misconfigured_json(self):
        res = corsy_parse.parse_corsy_output(REAL_CORSY_MISCONFIG_JSON)
        self.assertTrue(res["misconfigured"])
        self.assertEqual(len(res["findings"]), 1)
        finding = res["findings"][0]
        self.assertEqual(finding["url"], "https://example.com/api/user")
        self.assertEqual(finding["class"], "Reflected Origin")
        self.assertEqual(finding["severity"], "High")
        self.assertEqual(finding["acao_header"], "https://attacker.com")
        self.assertEqual(finding["acac_header"], "true")


if __name__ == "__main__":
    unittest.main()
