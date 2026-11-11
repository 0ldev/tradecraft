import unittest
from unittest.mock import MagicMock, patch

from tradecraft.adapters.craftcms_transform_rce_probe.execute import RawCraftResult, execute
from tradecraft.adapters.craftcms_transform_rce_probe.parse import parse_craft_result
from tradecraft.tools.craftcms_transform_rce_probe import CraftcmsTransformRceProbe


class TestCraftcmsTransformRceProbe(unittest.TestCase):
    def test_missing_target(self):
        res = execute(target="")
        self.assertIn("target is required", res.error)
        parsed = parse_craft_result(res)
        self.assertEqual(parsed["status"], "error")
        self.assertFalse(parsed["vulnerable"])

    @patch("requests.Session")
    def test_vulnerable_detection_gadget_reflection(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp_home = MagicMock()
        resp_home.status_code = 200
        resp_home.headers = {"X-Powered-By": "Craft CMS"}
        resp_home.text = "<html>Craft CMS</html>"

        resp_probe = MagicMock()
        resp_probe.status_code = 500
        resp_probe.text = '{"name":"Exception","message":"Setting unknown property: craft\\\\behaviors\\\\FieldLayoutBehavior"}'

        mock_session.get.return_value = resp_home
        mock_session.post.return_value = resp_probe

        raw = execute(target="https://craft.example.com")
        self.assertTrue(raw.craft_detected)
        self.assertTrue(raw.gadget_triggered)

        parsed = parse_craft_result(raw)
        self.assertTrue(parsed["vulnerable"])
        self.assertEqual(parsed["cve"], "CVE-2025-32432")
        self.assertEqual(parsed["status"], "vulnerable")
        self.assertIn("craft\\\\behaviors\\\\FieldLayoutBehavior", parsed["evidence_snippet"])

    @patch("requests.Session")
    def test_safe_endpoint_forbidden(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp_home = MagicMock()
        resp_home.status_code = 200
        resp_home.headers = {"X-Powered-By": "Craft CMS"}
        resp_home.text = "<html>Craft CMS</html>"

        resp_probe = MagicMock()
        resp_probe.status_code = 403
        resp_probe.text = "Forbidden"

        mock_session.get.return_value = resp_home
        mock_session.post.return_value = resp_probe

        raw = execute(target="craft.example.com")
        self.assertTrue(raw.craft_detected)
        self.assertFalse(raw.gadget_triggered)

        parsed = parse_craft_result(raw)
        self.assertFalse(parsed["vulnerable"])
        self.assertEqual(parsed["status"], "safe")

    @patch("requests.Session")
    def test_not_applicable_404(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp_home = MagicMock()
        resp_home.status_code = 404
        resp_home.headers = {}
        resp_home.text = "Not Found"

        resp_probe = MagicMock()
        resp_probe.status_code = 404
        resp_probe.text = "Not Found"

        mock_session.get.return_value = resp_home
        mock_session.post.return_value = resp_probe

        raw = execute(target="notcraft.example.com")
        parsed = parse_craft_result(raw)
        self.assertEqual(parsed["status"], "not_applicable")
        self.assertFalse(parsed["vulnerable"])

    @patch("tradecraft.adapters.craftcms_transform_rce_probe.execute.execute")
    def test_tool_run(self, mock_exec):
        mock_exec.return_value = RawCraftResult(
            target="craft.example.com",
            base_url="https://craft.example.com",
            endpoint_path="/actions/assets/generate-transform",
            gadget_triggered=True,
            craft_detected=True,
        )

        tool = CraftcmsTransformRceProbe()
        out = tool.run(target="craft.example.com")
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["cve"], "CVE-2025-32432")
        self.assertEqual(tool.extract_facts({}, out), [])


if __name__ == "__main__":
    unittest.main()
