"""
Unit tests for the retire_js adapter (execute and parse).
"""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tradecraft.adapters.retire_js import execute as retire_execute
from tradecraft.adapters.retire_js import parse as retire_parse

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

REAL_RETIRE_CLEAN_JSON = """{
  "version": "6.1.0",
  "data": [],
  "messages": []
}"""


class TestRetireJsExecute(unittest.TestCase):
    @mock.patch("requests.get")
    def test_fetch_script_urls(self, mock_get):
        html = """
        <html>
            <head>
                <script src="/js/app.js"></script>
                <script src="https://cdn.example.com/lib.js"></script>
                <script src="/js/app.js"></script>
            </head>
        </html>
        """
        mock_resp = mock.MagicMock()
        mock_resp.text = html
        mock_get.return_value = mock_resp

        urls = retire_execute.fetch_script_urls("https://example.com")
        self.assertEqual(urls, ["https://example.com/js/app.js", "https://cdn.example.com/lib.js"])

    @mock.patch("requests.get")
    def test_download_scripts(self, mock_get):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dest_dir = Path(tmp_dir)

            mock_resp = mock.MagicMock()
            mock_resp.status_code = 200
            mock_resp.iter_content = mock.MagicMock(return_value=[b"console.log('test');"])
            mock_get.return_value = mock_resp

            downloaded = retire_execute.download_scripts(
                ["https://example.com/js/app.js"],
                dest_dir,
            )
            self.assertEqual(len(downloaded), 1)
            self.assertTrue(downloaded[0].is_file())
            self.assertEqual(downloaded[0].read_text(), "console.log('test');")

    def test_execute_empty_target(self):
        res = retire_execute.execute("")
        self.assertEqual(res.error, "empty target")
        self.assertEqual(res.returncode, 1)

    @mock.patch("tradecraft.adapters.retire_js.execute.fetch_script_urls", return_value=[])
    @mock.patch("subprocess.run")
    def test_execute_missing_binary(self, mock_run, mock_fetch):
        mock_run.side_effect = FileNotFoundError()
        res = retire_execute.execute("https://example.com")
        self.assertEqual(res.error, "retire executable not found")

    @mock.patch("tradecraft.adapters.retire_js.execute.fetch_script_urls", return_value=[])
    @mock.patch("subprocess.run")
    def test_execute_timeout(self, mock_run, mock_fetch):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="retire", timeout=60)
        res = retire_execute.execute("https://example.com")
        self.assertEqual(res.error, "retire timed out after 60s")


class TestRetireJsParse(unittest.TestCase):
    def test_parse_empty_stdout(self):
        res = retire_parse.parse_retire_output("")
        self.assertFalse(res["vulnerable"])
        self.assertEqual(res["vulnerable_components"], [])
        self.assertEqual(res["summary"], [])

    def test_parse_clean_json(self):
        res = retire_parse.parse_retire_output(REAL_RETIRE_CLEAN_JSON)
        self.assertFalse(res["vulnerable"])
        self.assertEqual(res["vulnerable_components"], [])

    def test_parse_vulnerable_json(self):
        res = retire_parse.parse_retire_output(REAL_RETIRE_VULNERABLE_JSON)
        self.assertTrue(res["vulnerable"])
        self.assertEqual(len(res["vulnerable_components"]), 1)
        comp = res["vulnerable_components"][0]
        self.assertEqual(comp["component"], "jquery")
        self.assertEqual(comp["version"], "1.6.1")
        self.assertEqual(comp["file"], "jquery.js")
        self.assertEqual(comp["vulnerabilities_count"], 1)
        self.assertEqual(res["summary"], ["jquery@1.6.1"])


if __name__ == "__main__":
    unittest.main()
