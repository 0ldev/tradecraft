import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tradecraft.cli import main
from tradecraft.execution.loop import EngagementResult
from tradecraft.execution.run_dir import (
    create_initial_manifest,
    create_run_dir,
    finalize_manifest,
    get_tradecraft_home,
    read_manifest,
    save_facts_json,
    update_latest_symlink,
)
from tradecraft.memory.facts import FactStore


class TestCli(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_defaults_to_run_directory_persistence(self, mock_run_eng):
        mock_run_eng.return_value = EngagementResult(
            report="Summary",
            findings=[],
            transcript=[],
            turns_used=1,
            stats={},
            run_id="run_123",
            run_dir=self.home / "targets" / "example.com" / "runs" / "run_123",
        )

        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(sys, "argv", ["tradecraft", "example.com", "--run-id", "run_123"]):
                main()

        self.assertTrue(mock_run_eng.called)
        kwargs = mock_run_eng.call_args[1]
        self.assertEqual(kwargs["target"], "example.com")
        self.assertEqual(kwargs["run_id"], "run_123")
        self.assertEqual(kwargs["mode"], "fresh")
        self.assertEqual(kwargs["seed_from"], None)
        self.assertEqual(kwargs["seed_context"], "")
        self.assertEqual(kwargs["guidance"], "")
        self.assertFalse(kwargs["allow_destructive"])
        self.assertTrue(str(kwargs["run_dir"]).endswith("example.com/runs/run_123"))
        self.assertTrue(kwargs["persist_log_path"].endswith("log.txt"))
        self.assertTrue(kwargs["persist_trace_path"].endswith("trace.jsonl"))
        self.assertTrue(kwargs["persist_evidence_dir"].endswith("evidence"))

    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_no_persist_opts_out(self, mock_run_eng):
        mock_run_eng.return_value = EngagementResult(
            report="Summary", findings=[], transcript=[], turns_used=1, stats={},
        )

        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                ["tradecraft", "example.com", "--no-persist"]
            ):
                main()

        self.assertTrue(mock_run_eng.called)
        kwargs = mock_run_eng.call_args[1]
        self.assertIsNone(kwargs["run_dir"])
        self.assertIsNone(kwargs["persist_log_path"])
        self.assertIsNone(kwargs["persist_trace_path"])
        self.assertIsNone(kwargs["persist_evidence_dir"])
        self.assertFalse(kwargs["allow_destructive"])

    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_guidance_flag_passes_through(self, mock_run_eng):
        mock_run_eng.return_value = EngagementResult(
            report="Summary", findings=[], transcript=[], turns_used=1, stats={},
        )

        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                ["tradecraft", "example.com", "--no-persist", "--guidance", "Focus on the login flow."]
            ):
                main()

        kwargs = mock_run_eng.call_args[1]
        self.assertEqual(kwargs["guidance"], "Focus on the login flow.")

    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_allow_destructive_flag_passes_true(self, mock_run_eng):
        mock_run_eng.return_value = EngagementResult(
            report="Summary", findings=[], transcript=[], turns_used=1, stats={},
        )
        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                ["tradecraft", "example.com", "--no-persist", "--allow-destructive"]
            ):
                main()

        self.assertTrue(mock_run_eng.called)
        kwargs = mock_run_eng.call_args[1]
        self.assertTrue(kwargs["allow_destructive"])

    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_allow_destructive_categories_flag_parses_to_frozenset(self, mock_run_eng):
        mock_run_eng.return_value = EngagementResult(
            report="Summary", findings=[], transcript=[], turns_used=1, stats={},
        )
        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                ["tradecraft", "example.com", "--no-persist",
                 "--allow-destructive-categories", "code_execution, state_mutation"]
            ):
                main()

        self.assertTrue(mock_run_eng.called)
        kwargs = mock_run_eng.call_args[1]
        self.assertFalse(kwargs["allow_destructive"])
        self.assertEqual(kwargs["allow_destructive_categories"], frozenset({"code_execution", "state_mutation"}))

    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_no_allow_destructive_categories_flag_is_empty_frozenset(self, mock_run_eng):
        mock_run_eng.return_value = EngagementResult(
            report="Summary", findings=[], transcript=[], turns_used=1, stats={},
        )
        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(sys, "argv", ["tradecraft", "example.com", "--no-persist"]):
                main()

        kwargs = mock_run_eng.call_args[1]
        self.assertEqual(kwargs["allow_destructive_categories"], frozenset())

    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_credential_budget_flag_passes_through(self, mock_run_eng):
        mock_run_eng.return_value = EngagementResult(
            report="Summary", findings=[], transcript=[], turns_used=1, stats={},
        )
        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                ["tradecraft", "example.com", "--no-persist", "--credential-budget", "10"]
            ):
                main()

        kwargs = mock_run_eng.call_args[1]
        self.assertEqual(kwargs["credential_budget"], 10)

    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_no_credential_budget_flag_passes_none(self, mock_run_eng):
        mock_run_eng.return_value = EngagementResult(
            report="Summary", findings=[], transcript=[], turns_used=1, stats={},
        )
        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(sys, "argv", ["tradecraft", "example.com", "--no-persist"]):
                main()

        kwargs = mock_run_eng.call_args[1]
        self.assertIsNone(kwargs["credential_budget"])

    def test_cli_credential_budget_below_one_exits_with_error(self):
        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                ["tradecraft", "example.com", "--no-persist", "--credential-budget", "0"]
            ):
                with self.assertRaises(SystemExit) as ctx:
                    main()
                self.assertEqual(ctx.exception.code, 1)

    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_explicit_flags_override_defaults(self, mock_run_eng):
        mock_run_eng.return_value = EngagementResult(
            report="Summary", findings=[], transcript=[], turns_used=1, stats={},
        )

        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                [
                    "tradecraft", "example.com",
                    "--log", "/custom/log.txt",
                    "--trace", "/custom/trace.jsonl",
                    "--evidence-dir", "/custom/evidence",
                ]
            ):
                main()

        self.assertTrue(mock_run_eng.called)
        kwargs = mock_run_eng.call_args[1]
        self.assertEqual(kwargs["persist_log_path"], "/custom/log.txt")
        self.assertEqual(kwargs["persist_trace_path"], "/custom/trace.jsonl")
        self.assertEqual(kwargs["persist_evidence_dir"], "/custom/evidence")

    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_seed_from_latest_complement_mode(self, mock_run_eng):
        target = "example.com"
        rid, run_dir = create_run_dir(target, run_id="prior_run_1", tradecraft_home=self.home)
        target_dir = self.home / "targets" / target
        create_initial_manifest(run_dir, rid, target, "model", 0)
        finalize_manifest(run_dir, turns_used=5, findings_count=1, ended_at="2026-11-01T10:00:00Z")
        facts = FactStore()
        facts.merge_port("example.com", 443, {"service": "https"})
        save_facts_json(run_dir, facts)
        (run_dir / "log.txt").write_text("FINDING: 443 open\n", encoding="utf-8")
        update_latest_symlink(target_dir, rid)

        mock_run_eng.return_value = EngagementResult(
            report="Second run report", findings=[], transcript=[], turns_used=2, stats={},
        )

        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                ["tradecraft", "example.com", "--seed-from", "latest"]
            ):
                main()

        self.assertTrue(mock_run_eng.called)
        kwargs = mock_run_eng.call_args[1]
        self.assertEqual(kwargs["mode"], "complement")
        self.assertEqual(kwargs["seed_from"], "prior_run_1")
        self.assertIn("--- Known from a prior engagement (run prior_run_1, ended 2026-11-01T10:00:00Z) ---", kwargs["seed_context"])
        self.assertIn("example.com:443 -- service=https", kwargs["seed_context"])
        self.assertIn("FINDING: 443 open", kwargs["seed_context"])

    def test_cli_seed_from_different_target_exits_with_error(self):
        targetA = "targetA.com"
        rid, run_dir = create_run_dir(targetA, run_id="run_a", tradecraft_home=self.home)
        create_initial_manifest(run_dir, rid, targetA, "model", 0)
        finalize_manifest(run_dir, turns_used=3, findings_count=0, ended_at="2026-11-01T10:00:00Z")

        # Try to run against targetB with --seed-from run_a
        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                ["tradecraft", "targetB.com", "--seed-from", "run_a"]
            ):
                with self.assertRaises(SystemExit) as ctx:
                    main()
                self.assertEqual(ctx.exception.code, 1)

    @mock.patch("tradecraft.cli.generate_report")
    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_report_default_path(self, mock_run_eng, mock_gen_report):
        rid, run_dir = create_run_dir("example.com", run_id="run_rep_1", tradecraft_home=self.home)
        mock_run_eng.return_value = EngagementResult(
            report="Summary", findings=["f1"], transcript=[], turns_used=1, stats={},
            run_id=rid, run_dir=run_dir,
        )
        mock_gen_report.return_value = "# Report Content"

        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                ["tradecraft", "example.com", "--run-id", rid, "--report"]
            ):
                main()

        mock_gen_report.assert_called_once()
        expected_report_path = run_dir / "report.md"
        self.assertTrue(expected_report_path.is_file())
        self.assertEqual(expected_report_path.read_text(encoding="utf-8"), "# Report Content")

    @mock.patch("tradecraft.cli.generate_report")
    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_report_custom_path_and_model(self, mock_run_eng, mock_gen_report):
        rid, run_dir = create_run_dir("example.com", run_id="run_rep_2", tradecraft_home=self.home)
        mock_run_eng.return_value = EngagementResult(
            report="Summary", findings=["f1"], transcript=[], turns_used=1, stats={},
            run_id=rid, run_dir=run_dir,
        )
        mock_gen_report.return_value = "# Custom Report Content"
        custom_out = self.home / "custom_report.md"

        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                [
                    "tradecraft", "example.com",
                    "--run-id", rid, "--report", str(custom_out),
                    "--report-model", "custom-report-llm",
                ]
            ):
                main()

        mock_gen_report.assert_called_once()
        self.assertEqual(mock_gen_report.call_args[1]["model"], "custom-report-llm")
        self.assertTrue(custom_out.is_file())
        self.assertEqual(custom_out.read_text(encoding="utf-8"), "# Custom Report Content")

    @mock.patch("tradecraft.cli.generate_report")
    @mock.patch("tradecraft.cli.run_engagement")
    def test_cli_report_refusal_skips_output_and_prints_warning(self, mock_run_eng, mock_gen_report):
        rid, run_dir = create_run_dir("example.com", run_id="run_rep_3", tradecraft_home=self.home)
        mock_run_eng.return_value = EngagementResult(
            report="Nothing", findings=[], transcript=[], turns_used=1, stats={},
            run_id=rid, run_dir=run_dir,
        )
        mock_gen_report.return_value = None
        custom_out = self.home / "never_created.md"

        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys, "argv",
                [
                    "tradecraft", "example.com",
                    "--run-id", rid, "--report", str(custom_out),
                ]
            ):
                with mock.patch("sys.stderr", new_callable=mock.MagicMock) as mock_stderr:
                    main()

        self.assertFalse(custom_out.exists())
        printed = "".join(call.args[0] for call in mock_stderr.write.call_args_list if call.args)
        self.assertIn("nothing to report -- no findings or facts logged, skipping --report output", printed)
