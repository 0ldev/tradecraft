"""
Unit tests for decoupled standalone reporting, evidence hydration, turn-history
reconstruction, and multi-format exporters (md, html, json, sarif).
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
from tradecraft.execution.run_dir import (
    create_initial_manifest,
    create_run_dir,
    finalize_manifest,
    save_facts_json,
    update_latest_symlink,
)
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.facts import FactStore
from tradecraft.reporting.generator import (
    generate_reports_from_bundle,
    normalize_report_formats,
    write_bundle_reports,
)
from tradecraft.reporting.loader import (
    load_run_bundle,
    parse_facts_from_state_block,
    parse_log_text,
    resolve_report_run_dir,
)

REAL_LOG_WITH_RETRACTION = """note: Target = a Magento 2 e-commerce store.
FINDING #1 [evidence: http_request:admin.example.com.br/rest/V1/products]: admin.example.com.br hosts a live Magento 2 backend served directly by nginx/1.14.1 with NO Cloudflare/CDN/WAF in front.
FINDING #2 [evidence: graphql_introspect:admin.example.com.br]: GraphQL introspection is ENABLED on https://admin.example.com.br/graphql (type_count=506).
FINDING #3 [unverified: no evidence_id]: Suspected open Redis instance on port 6379.
note: Finding #3 retracted: Port 6379 returned connection reset; not an active Redis daemon.
"""

REAL_STATE_MSG_WITH_FACTS = """[Engagement state, refreshed every turn. This is context from the harness, not a message from the operator.]

## Engagement Log So Far

Your own notes/findings.

FINDING #1 [evidence: http_request:admin.example.com.br/rest/V1/products]: Magento 2 backend.

## Known Facts

What tools have reported so far, deduplicated per port -- not your own analysis, just the raw record.

admin.example.com.br:80 -- state=open, service=http, version=nginx 1.14.1
admin.example.com.br:443 -- live=True, http_status=200, evidence=graphql_introspect:admin.example.com.br,http_request:admin.example.com.br, sqli_tested=True

## Engagement Budget

No turn limit for this engagement -- investigate as thoroughly as the target's attack surface warrants. No conversation trimming has happened yet."""


class TestStandaloneReporting(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home = Path(self.temp_dir.name)
        self.target = "example.com.br"
        self.run_id, self.run_dir = create_run_dir(
            self.target,
            run_id="20261106T124433Z_570adb",
            tradecraft_home=self.home,
        )
        self.target_dir = self.home / "targets" / self.target

        create_initial_manifest(
            run_dir=self.run_dir,
            run_id=self.run_id,
            target=self.target,
            model="openai/qwen3.8-27b",
            max_turns=0,
            profile="full",
            allow_destructive=True,
            started_at="2026-11-06T12:44:33Z",
        )
        finalize_manifest(
            run_dir=self.run_dir,
            turns_used=2,
            findings_count=2,
            ended_at="2026-11-06T13:00:00Z",
        )

        # Persist log.txt with active findings, unverified finding, and a retraction note
        (self.run_dir / "log.txt").write_text(REAL_LOG_WITH_RETRACTION, encoding="utf-8")

        # Persist evidence files matching FINDING #1 and FINDING #2
        ev_store = EvidenceStore(persist_dir=self.run_dir / "evidence")
        ev_store.save(
            "admin.example.com.br/rest/V1/products",
            "http_request",
            {
                "status_code": 401,
                "server": "nginx/1.14.1",
                "raw_body": '{"message":"The consumer isn\'t authorized"}',
            },
        )
        ev_store.save(
            "admin.example.com.br",
            "graphql_introspect",
            {
                "url": "https://admin.example.com.br/graphql",
                "introspection_enabled": True,
                "type_count": 506,
            },
        )

        # Persist facts.json
        facts = FactStore()
        facts.merge_port("admin.example.com.br", 80, {"state": "open", "service": "http", "version": "nginx 1.14.1"})
        facts.merge_port(
            "admin.example.com.br",
            443,
            {
                "live": True,
                "http_status": 200,
                "sqli_tested": True,
                "evidence": "graphql_introspect:admin.example.com.br,http_request:admin.example.com.br/rest/V1/products",
            },
        )
        save_facts_json(self.run_dir, facts)

        # Persist 2-turn trace.jsonl with tool calls, tool results, reasoning, and final stop message
        trace_turn1 = {
            "index": 1,
            "turn": 1,
            "call_kind": "turn",
            "truncation_attempt": 0,
            "network_attempt": 0,
            "request": {
                "model": "openai/qwen3.8-27b",
                "messages": [
                    {"role": "system", "content": "system"},
                    {"role": "user", "content": "Begin the engagement against: example.com.br"},
                    {"role": "user", "content": REAL_STATE_MSG_WITH_FACTS},
                ],
            },
            "duration_seconds": 12.4,
            "timestamp": "2026-11-06T12:45:00+00:00",
            "content": "",
            "reasoning_content": "Let's probe the Magento GraphQL endpoint on admin.example.com.br.",
            "tool_call_names": ["graphql_introspect"],
            "finish_reason": "tool_calls",
            "usage": {"prompt_tokens": 2000, "completion_tokens": 150, "total_tokens": 2150},
        }
        trace_turn2 = {
            "index": 2,
            "turn": 2,
            "call_kind": "turn",
            "truncation_attempt": 0,
            "network_attempt": 0,
            "request": {
                "model": "openai/qwen3.8-27b",
                "messages": [
                    {"role": "system", "content": "system"},
                    {"role": "user", "content": "Begin the engagement against: example.com.br"},
                    {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_gql_1",
                                "type": "function",
                                "function": {
                                    "name": "graphql_introspect",
                                    "arguments": json.dumps({"target": "https://admin.example.com.br/graphql"}),
                                },
                            }
                        ],
                    },
                    {
                        "role": "tool",
                        "tool_call_id": "call_gql_1",
                        "content": json.dumps({
                            "introspection_enabled": True,
                            "type_count": 506,
                            "evidence_id": "graphql_introspect:admin.example.com.br",
                        }),
                    },
                    {"role": "user", "content": REAL_STATE_MSG_WITH_FACTS},
                ],
            },
            "duration_seconds": 8.6,
            "timestamp": "2026-11-06T12:46:00+00:00",
            "content": "Completed assessment of example.com.br. Key exposure is the un-fronted Magento 2 admin host.",
            "reasoning_content": "All high-priority leads verified. Ready to conclude.",
            "tool_call_names": [],
            "finish_reason": "stop",
            "usage": {"prompt_tokens": 2400, "completion_tokens": 200, "total_tokens": 2600},
        }
        with open(self.run_dir / "trace.jsonl", "w", encoding="utf-8") as f:
            f.write(json.dumps(trace_turn1) + "\n")
            f.write(json.dumps(trace_turn2) + "\n")

        update_latest_symlink(self.target_dir, self.run_id)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_log_text_handles_retractions_and_hydrates_evidence(self):
        ev_store = EvidenceStore(persist_dir=self.run_dir / "evidence")
        active, retracted, notes, _ = parse_log_text(REAL_LOG_WITH_RETRACTION, evidence_store=ev_store)

        self.assertEqual(len(active), 2)
        self.assertEqual(len(retracted), 1)
        self.assertEqual(active[0].finding_id, 1)
        self.assertTrue(active[0].verified)
        self.assertEqual(active[0].tool_id, "http_request")
        self.assertEqual(active[0].asset, "admin.example.com.br/rest/V1/products")
        self.assertIn("nginx/1.14.1", active[0].evidence_snippet)

        self.assertEqual(retracted[0].finding_id, 3)
        self.assertTrue(retracted[0].retracted)
        self.assertEqual(
            retracted[0].retraction_reason,
            "Port 6379 returned connection reset; not an active Redis daemon.",
        )

    def test_recover_facts_from_trace_when_facts_json_missing(self):
        (self.run_dir / "facts.json").unlink()
        bundle = load_run_bundle(self.run_dir)
        records = dict(bundle.facts.sorted_records())
        self.assertIn(("admin.example.com.br", 80), records)
        self.assertIn(("admin.example.com.br", 443), records)
        self.assertEqual(records[("admin.example.com.br", 80)]["version"], "nginx 1.14.1")
        self.assertIn(
            "graphql_introspect:admin.example.com.br,http_request:admin.example.com.br",
            records[("admin.example.com.br", 443)]["evidence"],
        )

    def test_resolve_report_run_dir_fallback_without_latest_symlink(self):
        (self.target_dir / "latest").unlink()
        resolved = resolve_report_run_dir(target=self.target, run="latest", tradecraft_home=self.home)
        self.assertEqual(resolved, self.run_dir.resolve())

    def test_load_run_bundle_reconstructs_history_and_closing_notes(self):
        bundle = load_run_bundle(self.run_dir)
        self.assertEqual(bundle.target, "example.com.br")
        self.assertEqual(bundle.turns_used, 2)
        self.assertEqual(len(bundle.history), 2)
        self.assertEqual(bundle.history[0].turn, 1)
        self.assertEqual(len(bundle.history[0].tool_calls), 1)
        tc = bundle.history[0].tool_calls[0]
        self.assertEqual(tc.name, "graphql_introspect")
        self.assertEqual(tc.arguments, {"target": "https://admin.example.com.br/graphql"})
        self.assertEqual(tc.evidence_id, "graphql_introspect:admin.example.com.br")
        self.assertIn("un-fronted Magento 2 admin host", bundle.closing_notes)

    def test_generate_all_formats_deterministic_no_llm(self):
        bundle = load_run_bundle(self.run_dir)
        with mock.patch("litellm.completion") as mock_comp:
            outputs = generate_reports_from_bundle(bundle, formats="all", use_llm=False)
            mock_comp.assert_not_called()

        self.assertIsNotNone(outputs)
        self.assertEqual(set(outputs.keys()), {"md", "html", "json", "sarif"})

        md = outputs["md"]
        self.assertIn("# Security Assessment Report: example.com.br", md)
        self.assertIn("### Attached Tool Proof (Evidence Store)", md)
        self.assertIn("## Retracted Hypotheses (Ruled Out During Engagement)", md)
        self.assertIn("Port 6379 returned connection reset", md)

        html_out = outputs["html"]
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("tab-findings", html_out)
        self.assertIn("tab-surface", html_out)
        self.assertIn("tab-history", html_out)
        self.assertIn("tab-evidence", html_out)
        self.assertIn("Turn #1", html_out)
        self.assertIn("graphql_introspect", html_out)
        self.assertIn("sqli_tested=True", html_out)
        self.assertIn("RETRACTED #3", html_out)

        json_data = json.loads(outputs["json"])
        self.assertEqual(json_data["schema_version"], "1.0")
        self.assertEqual(json_data["target"], "example.com.br")
        self.assertEqual(len(json_data["findings"]), 2)
        self.assertEqual(len(json_data["retracted_findings"]), 1)
        self.assertEqual(len(json_data["history"]), 2)

        sarif_data = json.loads(outputs["sarif"])
        self.assertEqual(sarif_data["version"], "2.1.0")
        results = sarif_data["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["ruleId"], "tradecraft/http_request")
        self.assertTrue(results[0]["properties"]["verified"])
        self.assertIn("nginx/1.14.1", results[0]["properties"]["evidence_snippet"])

    def test_guidance_surfaces_in_md_and_html_when_present_and_omitted_when_absent(self):
        bundle = load_run_bundle(self.run_dir)
        with mock.patch("litellm.completion"):
            outputs = generate_reports_from_bundle(bundle, formats="md,html", use_llm=False)
        self.assertNotIn("Operator guidance", outputs["md"])
        self.assertNotIn("Operator Guidance", outputs["html"])

        bundle.manifest["guidance"] = "Focus on the login flow & <admin> panel."
        with mock.patch("litellm.completion"):
            outputs = generate_reports_from_bundle(bundle, formats="md,html", use_llm=False)
        self.assertIn("**Operator guidance:** Focus on the login flow & <admin> panel.", outputs["md"])
        self.assertIn("Operator Guidance:</strong>", outputs["html"])
        self.assertIn("Focus on the login flow &amp; &lt;admin&gt; panel.", outputs["html"])

    def test_cli_report_subcommand_writes_files(self):
        out_dir = self.home / "exported_reports"
        with mock.patch.dict(os.environ, {"TRADECRAFT_HOME": str(self.home)}):
            with mock.patch.object(
                sys,
                "argv",
                [
                    "tradecraft",
                    "report",
                    "--target",
                    self.target,
                    "--format",
                    "all",
                    "--no-llm",
                    "--output",
                    str(out_dir),
                ],
            ):
                with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()

        self.assertTrue((out_dir / "report.md").is_file())
        self.assertTrue((out_dir / "report.html").is_file())
        self.assertTrue((out_dir / "report.json").is_file())
        self.assertTrue((out_dir / "report.sarif.json").is_file())
        stdout_text = mock_stdout.getvalue()
        self.assertIn("wrote md report to", stdout_text)
        self.assertIn("wrote html report to", stdout_text)
        self.assertIn("wrote json report to", stdout_text)
        self.assertIn("wrote sarif report to", stdout_text)

    def test_normalize_report_formats_validation(self):
        self.assertEqual(normalize_report_formats("md,html"), ["md", "html"])
        self.assertEqual(normalize_report_formats("all"), ["md", "html", "json", "sarif"])
        with self.assertRaises(ValueError):
            normalize_report_formats("pdf_invalid")


if __name__ == "__main__":
    unittest.main()
