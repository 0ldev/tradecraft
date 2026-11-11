import unittest
from unittest.mock import MagicMock, patch

from tradecraft.adapters.flowise_token_leak_probe.execute import RawFlowiseResult, execute
from tradecraft.adapters.flowise_token_leak_probe.parse import parse_flowise_result
from tradecraft.tools.flowise_token_leak_probe import FlowiseTokenLeakProbe


class TestFlowiseTokenLeakProbe(unittest.TestCase):
    def test_missing_target(self):
        res = execute(target="")
        self.assertIn("target is required", res.error)
        parsed = parse_flowise_result(res)
        self.assertEqual(parsed["status"], "error")
        self.assertFalse(parsed["vulnerable"])

    @patch("requests.Session")
    def test_vulnerable_detection_token_leaked(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp_home = MagicMock()
        resp_home.status_code = 200
        resp_home.headers = {}
        resp_home.text = "<html><title>Flowise</title></html>"

        resp_ping = MagicMock()
        resp_ping.status_code = 200
        resp_ping.text = "pong"

        resp_forgot = MagicMock()
        resp_forgot.status_code = 201
        resp_forgot.json.return_value = {
            "user": {
                "email": "admin@local",
                "tempToken": "sec_tok_99182312a0f8",
            }
        }
        resp_forgot.text = '{"user": {"email": "admin@local", "tempToken": "sec_tok_99182312a0f8"}}'

        mock_session.get.side_effect = [resp_home, resp_ping]
        mock_session.post.return_value = resp_forgot

        raw = execute(target="http://flowise.internal:3000", email="admin@local")
        self.assertTrue(raw.flowise_detected)
        self.assertTrue(raw.token_leaked)
        self.assertIn("sec_tok_9918", raw.leaked_token_preview)

        parsed = parse_flowise_result(raw)
        self.assertTrue(parsed["vulnerable"])
        self.assertEqual(parsed["cve"], "CVE-2025-58434")
        self.assertEqual(parsed["status"], "vulnerable")
        self.assertTrue(parsed["token_leaked"])

    @patch("requests.Session")
    def test_safe_response_unregistered_user(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp_home = MagicMock()
        resp_home.status_code = 200
        resp_home.headers = {}
        resp_home.text = "<html><title>Flowise</title></html>"

        resp_ping = MagicMock()
        resp_ping.status_code = 200
        resp_ping.text = "pong"

        resp_forgot = MagicMock()
        resp_forgot.status_code = 404
        resp_forgot.json.return_value = {"message": "Unregistered user"}
        resp_forgot.text = '{"message": "Unregistered user"}'

        mock_session.get.side_effect = [resp_home, resp_ping]
        mock_session.post.return_value = resp_forgot

        raw = execute(target="ai.corp.local")
        self.assertTrue(raw.flowise_detected)
        self.assertFalse(raw.token_leaked)

        parsed = parse_flowise_result(raw)
        self.assertFalse(parsed["vulnerable"])
        self.assertEqual(parsed["status"], "partial")

    @patch("requests.Session")
    def test_not_applicable_404(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp_home = MagicMock()
        resp_home.status_code = 404
        resp_home.headers = {}
        resp_home.text = "Not Found"

        resp_ping = MagicMock()
        resp_ping.status_code = 404
        resp_ping.text = "Not Found"

        resp_forgot = MagicMock()
        resp_forgot.status_code = 404
        resp_forgot.text = "Not Found"

        mock_session.get.side_effect = [resp_home, resp_ping]
        mock_session.post.return_value = resp_forgot

        raw = execute(target="notflowise.example.com")
        parsed = parse_flowise_result(raw)
        self.assertEqual(parsed["status"], "not_applicable")
        self.assertFalse(parsed["vulnerable"])

    @patch("tradecraft.adapters.flowise_token_leak_probe.execute.execute")
    def test_tool_run(self, mock_exec):
        mock_exec.return_value = RawFlowiseResult(
            target="flowise.internal",
            base_url="https://flowise.internal",
            token_leaked=True,
            flowise_detected=True,
            leaked_token_preview="sec_token...",
        )

        tool = FlowiseTokenLeakProbe()
        out = tool.run(target="flowise.internal")
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["cve"], "CVE-2025-58434")
        self.assertEqual(tool.extract_facts({}, out), [])


if __name__ == "__main__":
    unittest.main()
