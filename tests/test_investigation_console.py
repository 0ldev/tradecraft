"""
Unit tests for the post-run investigation console (tradecraft/reporting/console.py).
"""
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tradecraft.cli import main
from tradecraft.execution.run_dir import create_run_dir, update_latest_symlink
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.reporting.console import (
    InvestigationConsole,
    resolve_console_run_dir,
    run_repl,
)

REAL_CAPTURED_LOG = """note: Starting engagement on examplepaint.com.br. Plan: 1) subfinder, 2) dnsx, 3) nmap.
FINDING: Apex examplepaint.com.br (192.0.2.10) runs Apache + PHP 7.0.33 (end-of-life since Jan 2019) — detected via httpx_probe/whatweb. No WAF in front.
FINDING: cPanel login interface live at cpanel.examplepaint.com.br (200, "cPanel Login", Apache). webdisk.examplepaint.com.br returns 401 (cPanel Basic auth file manager).
FINDING: Mail/DNS surface on 192.0.2.10: Exim 4.92 (465/587), Dovecot pop3d/imapd (110/143), imaps/pop3s (993/995), PowerDNS Authoritative 4.1.1 on 53.
"""

REAL_CAPTURED_FACTS = [
    {
        "host": "materiais.examplepaint.com.br",
        "port": 443,
        "http_status": 404,
        "evidence": "httpx_probe:materiais.examplepaint.com.br",
    },
    {
        "host": "examplepaint.com.br",
        "port": 53,
        "dns_a": "192.0.2.10",
        "dns_mx": "mx.core.examplehost.net,mx.a.examplehost.net",
        "evidence": "dnsx:examplepaint.com.br",
    },
]

REAL_TRACE_RECORD = {
    "index": 1,
    "turn": 1,
    "call_kind": "turn",
    "truncation_attempt": 0,
    "network_attempt": 0,
    "request": {"model": "openai/qwen3.8-27b", "messages": []},
    "duration_seconds": 18.9,
    "timestamp": "2026-11-02T01:17:16.922041+00:00",
    "content": "",
    "reasoning_content": "I'll start this engagement by performing DNS reconnaissance against examplepaint.com.br.",
    "tool_call_names": ["dnsx"],
    "finish_reason": "tool_calls",
    "usage": {"completion_tokens": 85, "prompt_tokens": 4932, "total_tokens": 5017},
}


class TestInvestigationConsole(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home = Path(self.temp_dir.name)
        self.target = "examplepaint.com.br"
        self.run_id, self.run_dir = create_run_dir(self.target, run_id="20261102T011716Z_test", tradecraft_home=self.home)
        self.target_dir = self.home / "targets" / self.target

        (self.run_dir / "log.txt").write_text(REAL_CAPTURED_LOG, encoding="utf-8")

        (self.run_dir / "facts.json").write_text(json.dumps(REAL_CAPTURED_FACTS, indent=2), encoding="utf-8")

        (self.run_dir / "trace.jsonl").write_text(json.dumps(REAL_TRACE_RECORD) + "\n", encoding="utf-8")

        store = EvidenceStore(persist_dir=self.run_dir / "evidence")
        store.save("examplepaint.com.br", "dnsx", {"a": ["192.0.2.10"]})

        update_latest_symlink(self.target_dir, self.run_id)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_resolve_console_run_dir_mutual_exclusion(self):
        with self.assertRaises(ValueError):
            resolve_console_run_dir(run_dir=self.run_dir, target=self.target, tradecraft_home=self.home)
        with self.assertRaises(ValueError):
            resolve_console_run_dir(tradecraft_home=self.home)

    def test_resolve_console_run_dir_via_run_dir(self):
        resolved = resolve_console_run_dir(run_dir=self.run_dir, tradecraft_home=self.home)
        self.assertEqual(resolved, self.run_dir.resolve())

    def test_resolve_console_run_dir_via_target_latest(self):
        resolved = resolve_console_run_dir(target=self.target, tradecraft_home=self.home)
        self.assertEqual(resolved, self.run_dir.resolve())

    def test_resolve_console_run_dir_via_target_explicit_run(self):
        resolved = resolve_console_run_dir(target=self.target, run=self.run_id, tradecraft_home=self.home)
        self.assertEqual(resolved, self.run_dir.resolve())

    def test_resolve_console_run_dir_missing_log_txt_raises(self):
        empty_run = self.home / "targets" / "empty_target" / "runs" / "empty_run"
        empty_run.mkdir(parents=True, exist_ok=True)
        with self.assertRaises(FileNotFoundError) as ctx:
            resolve_console_run_dir(run_dir=empty_run, tradecraft_home=self.home)
        self.assertIn("has no log.txt -- not a valid run directory", str(ctx.exception))

    def test_system_prompt_includes_log_and_facts(self):
        console = InvestigationConsole(self.run_dir)
        prompt = console.system_prompt
        self.assertIn("You are answering an operator's questions", prompt)
        self.assertIn("--- Engagement log ---", prompt)
        self.assertIn("Apex examplepaint.com.br (192.0.2.10) runs Apache + PHP 7.0.33", prompt)
        self.assertIn("--- Attack surface facts ---", prompt)
        self.assertIn("materiais.examplepaint.com.br", prompt)

    def test_graceful_degradation_when_facts_missing(self):
        (self.run_dir / "facts.json").unlink()
        console = InvestigationConsole(self.run_dir)
        prompt = console.system_prompt
        self.assertIn("(no attack-surface summary available for this run -- ask via search_log or read_evidence instead)", prompt)

    def test_search_log_case_insensitive_verbatim(self):
        console = InvestigationConsole(self.run_dir)
        matches = console.search_log("apache")
        self.assertEqual(len(matches), 2)
        self.assertTrue(matches[0].startswith("FINDING: Apex examplepaint.com.br"))
        self.assertTrue(matches[1].startswith("FINDING: cPanel login"))

        no_matches = console.search_log("nonexistent_term")
        self.assertEqual(no_matches, [])

    def test_get_turn_reasoning_matching_and_missing(self):
        console = InvestigationConsole(self.run_dir)
        turn1 = console.get_turn_reasoning(1)
        self.assertEqual(turn1["turn"], 1)
        self.assertEqual(len(turn1["calls"]), 1)
        call = turn1["calls"][0]
        self.assertEqual(call["tool_call_names"], ["dnsx"])
        self.assertIn("DNS reconnaissance", call["reasoning_content"])
        self.assertNotIn("request", call)
        self.assertNotIn("usage", call)

        # Turn 2 does not exist
        turn2 = console.get_turn_reasoning(2)
        self.assertEqual(turn2, {"turn": 2, "calls": []})

    def test_get_turn_reasoning_missing_trace_file(self):
        (self.run_dir / "trace.jsonl").unlink()
        console = InvestigationConsole(self.run_dir)
        res = console.get_turn_reasoning(1)
        self.assertEqual(res, {"error": "no trace file found in this run"})

    def test_read_and_search_evidence(self):
        console = InvestigationConsole(self.run_dir)
        ev = console.read_evidence("examplepaint.com.br", "dnsx")
        self.assertEqual(ev.get("evidence"), {"a": ["192.0.2.10"]})
        self.assertEqual(ev.get("target"), "examplepaint.com.br")
        self.assertEqual(ev.get("tool"), "dnsx")

        search_res = console.search_evidence("192.0.2.10")
        self.assertIn("matches", search_res)
        self.assertEqual(len(search_res["matches"]), 1)

    def test_evidence_tools_missing_evidence_dir(self):
        import shutil
        shutil.rmtree(self.run_dir / "evidence")
        console = InvestigationConsole(self.run_dir)
        self.assertEqual(console.read_evidence("examplepaint.com.br", "dnsx"), {"error": "no evidence directory found in this run"})
        self.assertEqual(console.search_evidence("test"), {"error": "no evidence directory found in this run"})

    @mock.patch("litellm.completion")
    def test_ask_one_shot_with_tool_call(self, mock_comp):
        console = InvestigationConsole(self.run_dir)

        # Turn 1: model calls search_log
        mock_tc = mock.MagicMock()
        mock_tc.id = "call_1"
        mock_tc.function.name = "search_log"
        mock_tc.function.arguments = json.dumps({"query": "Exim"})

        resp_turn1 = mock.MagicMock(choices=[mock.MagicMock(message=mock.MagicMock(
            content=None,
            tool_calls=[mock_tc],
            reasoning_content="Let me search the log for Exim.",
        ))])

        # Turn 2: model produces final answer
        resp_turn2 = mock.MagicMock(choices=[mock.MagicMock(message=mock.MagicMock(
            content="Exim 4.92 is running on ports 465 and 587.",
            tool_calls=None,
            reasoning_content=None,
        ))])

        mock_comp.side_effect = [resp_turn1, resp_turn2]

        answer = console.ask("What mail software was detected?")
        self.assertEqual(answer, "Exim 4.92 is running on ports 465 and 587.")
        self.assertEqual(mock_comp.call_count, 2)

        # Verify tool result was delivered in conversation
        tool_msg = console.conversation[3]
        self.assertEqual(tool_msg["role"], "tool")
        self.assertEqual(tool_msg["name"], "search_log")
        self.assertIn("Exim 4.92", tool_msg["content"])

    @mock.patch("litellm.completion")
    def test_cli_chat_ask_one_shot(self, mock_comp):
        mock_comp.return_value = mock.MagicMock(choices=[mock.MagicMock(message=mock.MagicMock(
            content="The PHP version detected was 7.0.33.",
            tool_calls=None,
        ))])

        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                [
                    "tradecraft", "chat", "--target", self.target,
                    "--ask", "What PHP version was found?",
                ]
            ):
                with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()

        output = mock_stdout.getvalue()
        self.assertIn("The PHP version detected was 7.0.33.", output)

    @mock.patch("builtins.input", side_effect=["exit"])
    def test_repl_banner_and_clean_exit(self, mock_input):
        console = InvestigationConsole(self.run_dir)
        with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            run_repl(console)

        output = mock_stdout.getvalue()
        self.assertIn("Tradecraft Console:", output)
        self.assertIn("found: log.txt, trace.jsonl, evidence/, facts.json", output)

    def test_cli_chat_run_with_run_dir_fails(self):
        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                [
                    "tradecraft", "chat", "--run-dir", str(self.run_dir),
                    "--run", "latest",
                ]
            ):
                with self.assertRaises(SystemExit) as ctx:
                    main()
                self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
