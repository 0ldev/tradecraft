import unittest
from unittest.mock import MagicMock, patch

from tradecraft.adapters.drupal_jsonapi_sqli_probe.execute import RawDrupalSqliResult, execute
from tradecraft.adapters.drupal_jsonapi_sqli_probe.parse import parse_drupal_sqli_result
from tradecraft.tools.drupal_jsonapi_sqli_probe import DrupalJsonapiSqliProbe


class TestDrupalJsonapiSqliProbe(unittest.TestCase):
    def test_missing_target(self):
        res = execute(target="")
        self.assertIn("target is required", res.error)
        parsed = parse_drupal_sqli_result(res)
        self.assertEqual(parsed["status"], "error")
        self.assertFalse(parsed["vulnerable"])

    @patch("requests.Session")
    def test_vulnerable_detection_pgsql_error(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        # Baseline response
        resp_base = MagicMock()
        resp_base.status_code = 200
        resp_base.headers = {
            "Content-Type": "application/vnd.api+json",
            "X-Generator": "Drupal 10 (https://www.drupal.org)",
        }
        resp_base.text = '{"data": []}'

        # Probe response with SQL syntax error
        resp_probe = MagicMock()
        resp_probe.status_code = 500
        resp_probe.headers = {"Content-Type": "application/vnd.api+json"}
        resp_probe.json.return_value = {
            "errors": [
                {
                    "title": "500 Internal Server Error",
                    "status": "500",
                    "detail": 'SQLSTATE[22P02]: Invalid text representation: 7 ERROR: invalid input syntax for integer: "RS_SQLI_TEST"',
                }
            ]
        }
        resp_probe.text = '{"errors": [{"detail": "invalid input syntax for integer: RS_SQLI_TEST"}]}'

        mock_session.get.side_effect = [resp_base, resp_probe]

        raw = execute(target="https://drupal.corp.local")
        self.assertTrue(raw.sqli_confirmed)
        self.assertTrue(raw.drupal_detected)

        parsed = parse_drupal_sqli_result(raw)
        self.assertTrue(parsed["vulnerable"])
        self.assertEqual(parsed["cve"], "CVE-2026-9082")
        self.assertEqual(parsed["status"], "vulnerable")
        self.assertIn("invalid input syntax for integer", parsed["error_detail"])

    @patch("requests.Session")
    def test_safe_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp_base = MagicMock()
        resp_base.status_code = 200
        resp_base.headers = {
            "Content-Type": "application/vnd.api+json",
            "X-Generator": "Drupal 10",
        }
        resp_base.text = '{"data": []}'

        resp_probe = MagicMock()
        resp_probe.status_code = 400
        resp_probe.headers = {"Content-Type": "application/vnd.api+json"}
        resp_probe.json.return_value = {
            "errors": [{"detail": "Invalid filter parameter format."}]
        }
        resp_probe.text = '{"errors": [{"detail": "Invalid filter parameter format."}]}'

        mock_session.get.side_effect = [resp_base, resp_probe]

        raw = execute(target="drupal.example.com")
        self.assertFalse(raw.sqli_confirmed)

        parsed = parse_drupal_sqli_result(raw)
        self.assertFalse(parsed["vulnerable"])
        self.assertEqual(parsed["status"], "safe")

    @patch("requests.Session")
    def test_not_applicable_404(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp_base = MagicMock()
        resp_base.status_code = 404
        resp_base.headers = {"Content-Type": "text/html"}
        resp_base.text = "Not Found"

        mock_session.get.return_value = resp_base

        raw = execute(target="notdrupal.example.com")
        parsed = parse_drupal_sqli_result(raw)
        self.assertEqual(parsed["status"], "not_applicable")
        self.assertFalse(parsed["vulnerable"])

    @patch("tradecraft.adapters.drupal_jsonapi_sqli_probe.execute.execute")
    def test_tool_run(self, mock_exec):
        mock_exec.return_value = RawDrupalSqliResult(
            target="drupal.example.com",
            base_url="https://drupal.example.com",
            path="/jsonapi/node/article",
            sqli_confirmed=True,
            drupal_detected=True,
            probe_error_detail="invalid input syntax for integer",
        )

        tool = DrupalJsonapiSqliProbe()
        out = tool.run(target="drupal.example.com")
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["cve"], "CVE-2026-9082")
        self.assertEqual(tool.extract_facts({}, out), [])


if __name__ == "__main__":
    unittest.main()
