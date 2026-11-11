import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tradecraft.execution.loop import run_engagement
from tradecraft.execution.run_dir import (
    create_run_dir,
    get_target_dir,
    load_facts_json,
    read_manifest,
)


class TestLoopPersistence(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @mock.patch("tradecraft.execution.loop._complete_with_retry")
    def test_run_engagement_persists_manifest_facts_and_symlink(self, mock_complete):
        # Mock LLM returning a final report immediately (no tool calls)
        mock_choice = mock.MagicMock()
        mock_choice.message.content = "Assessment complete. No issues found."
        mock_choice.message.tool_calls = None
        mock_choice.finish_reason = "stop"
        mock_response = mock.MagicMock()
        mock_response.choices = [mock_choice]
        mock_complete.return_value = mock_response

        target = "target.local"
        rid, run_dir = create_run_dir(target, run_id="20261101T150000Z_abcdef", tradecraft_home=self.home)
        target_dir = get_target_dir(target, self.home)

        result = run_engagement(
            target=target,
            model="test-model",
            run_dir=run_dir,
            run_id=rid,
            max_turns=1,
        )

        self.assertEqual(result.run_id, rid)
        self.assertEqual(result.run_dir, run_dir)
        self.assertEqual(result.turns_used, 1)

        manifest = read_manifest(run_dir)
        self.assertEqual(manifest["run_id"], rid)
        self.assertEqual(manifest["target"], target)
        self.assertEqual(manifest["mode"], "fresh")
        self.assertIsNotNone(manifest["started_at"])
        self.assertIsNotNone(manifest["ended_at"])
        self.assertEqual(manifest["turns_used"], 1)

        self.assertTrue((run_dir / "facts.json").is_file())

        latest_symlink = target_dir / "latest"
        self.assertTrue(latest_symlink.is_symlink())
        self.assertEqual(latest_symlink.resolve(), run_dir.resolve())

    @mock.patch("tradecraft.execution.loop._complete_with_retry")
    def test_run_engagement_records_tool_provenance_in_manifest(self, mock_complete):
        # Without this, a run directory on disk can't say afterwards whether
        # a destructive tool (sqli_login, ...) was actually available
        # for this run, or which profile/tool list produced it.
        mock_choice = mock.MagicMock()
        mock_choice.message.content = "Assessment complete."
        mock_choice.message.tool_calls = None
        mock_choice.finish_reason = "stop"
        mock_response = mock.MagicMock()
        mock_response.choices = [mock_choice]
        mock_complete.return_value = mock_response

        target = "target.local"
        rid, run_dir = create_run_dir(target, run_id="20261101T150100Z_abcdef", tradecraft_home=self.home)

        run_engagement(
            target=target,
            model="test-model",
            run_dir=run_dir,
            run_id=rid,
            max_turns=1,
            tool_ids=["nmap_scan", "sqli_login"],
            allow_destructive=True,
            profile="web",
        )

        manifest = read_manifest(run_dir)
        self.assertEqual(manifest["profile"], "web")
        self.assertEqual(manifest["tool_ids"], ["nmap_scan", "sqli_login"])
        self.assertEqual(manifest["allow_destructive"], True)

    @mock.patch("tradecraft.execution.loop._complete_with_retry")
    def test_run_engagement_records_and_renders_guidance(self, mock_complete):
        mock_choice = mock.MagicMock()
        mock_choice.message.content = "Assessment complete."
        mock_choice.message.tool_calls = None
        mock_choice.finish_reason = "stop"
        mock_response = mock.MagicMock()
        mock_response.choices = [mock_choice]
        mock_complete.return_value = mock_response

        target = "target.local"
        rid, run_dir = create_run_dir(target, run_id="20261101T150200Z_abcdef", tradecraft_home=self.home)

        run_engagement(
            target=target,
            model="test-model",
            run_dir=run_dir,
            run_id=rid,
            max_turns=1,
            guidance="Focus on the login flow.",
        )

        manifest = read_manifest(run_dir)
        self.assertEqual(manifest["guidance"], "Focus on the login flow.")

        # The actual system prompt sent to the LLM must carry the guidance block.
        sent_messages = mock_complete.call_args[1]["messages"]
        system_msg = next(m["content"] for m in sent_messages if m["role"] == "system")
        self.assertIn("## Operator Guidance", system_msg)
        self.assertIn("Focus on the login flow.", system_msg)
