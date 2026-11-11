import json
import tempfile
import unittest
from pathlib import Path

from tradecraft.cli import main as cli_main
from tradecraft.dataset import (
    build_datasets_from_sources,
    evaluate_run_checklist,
    extract_dpo_records,
    extract_sft_records,
    load_run_dataset_source,
    normalize_behaviors,
    normalize_dataset_formats,
    resolve_dataset_run_dirs,
)
from tradecraft.execution.run_dir import (
    create_initial_manifest,
    create_run_dir,
    finalize_manifest,
    update_latest_symlink,
)

SAMPLE_LOG = """note: Starting recon on example.com.br and admin.example.com.br (192.0.2.10).
FINDING #1 [evidence: graphql_introspect:admin.example.com.br]: GraphQL introspection enabled on admin.example.com.br/graphql exposing 506 types.
FINDING #2 [RETRACTED] [evidence: http_request:example.com.br]: Suspected open redirect on /login.
note: Finding #2 retracted: Location header stayed on same origin after follow-up check.
FINDING #3 [unverified: no evidence_id]: Speculative WAF bypass without tool evidence.
"""

SAMPLE_FACTS = [
    {
        "host": "example.com.br",
        "port": 443,
        "service": "https",
        "a_records": ["192.0.2.10"],
    },
    {
        "host": "admin.example.com.br",
        "port": 443,
        "service": "https",
        "arjun_params_discovered": ["id"],
    },
]


def _make_trace_records() -> list[dict]:
    tc_turn1 = [
        {
            "id": "call_sub_1",
            "type": "function",
            "function": {
                "name": "subfinder",
                "arguments": json.dumps({"target": "example.com.br"}),
            },
        },
        {
            "id": "call_gql_1",
            "type": "function",
            "function": {
                "name": "graphql_introspect",
                "arguments": json.dumps({"target": "https://admin.example.com.br/graphql"}),
            },
        },
    ]
    tc_turn2_retracted = [
        {
            "id": "call_find_2",
            "type": "function",
            "function": {
                "name": "log_finding",
                "arguments": json.dumps({
                    "finding": "Suspected open redirect on /login.",
                    "evidence_id": "http_request:example.com.br",
                }),
            },
        }
    ]
    tc_turn3_bad_tool = [
        {
            "id": "call_bad_3",
            "type": "function",
            "function": {
                "name": "nonexistent_scanner",
                "arguments": json.dumps({"target": "example.com.br"}),
            },
        }
    ]
    tc_turn5_post_nudge = [
        {
            "id": "call_read_ev_5",
            "type": "function",
            "function": {
                "name": "read_evidence",
                "arguments": json.dumps({
                    "target": "admin.example.com.br",
                    "tool": "graphql_introspect",
                }),
            },
        },
        {
            "id": "call_sqli_5",
            "type": "function",
            "function": {
                "name": "sqlmap_scan",
                "arguments": json.dumps({"target": "https://admin.example.com.br/item?id=1"}),
            },
        },
    ]

    return [
        # Turn 1 attempt 0: truncated
        {
            "index": 1,
            "turn": 1,
            "call_kind": "turn",
            "truncation_attempt": 0,
            "network_attempt": 0,
            "request": {
                "model": "openai/qwen3.8-27b",
                "messages": [
                    {"role": "system", "content": "Target: example.com.br"},
                    {"role": "user", "content": "Begin the engagement against: example.com.br"},
                    {"role": "user", "content": "## Known Facts\n(none)"},
                ],
                "tools": [{"type": "function", "function": {"name": "graphql_introspect"}}],
            },
            "duration_seconds": 4.0,
            "timestamp": "2026-11-07T01:00:00+00:00",
            "content": "",
            "reasoning_content": "Truncated reasoning mid-thought...",
            "tool_call_names": [],
            "tool_calls": [],
            "finish_reason": "length",
            "usage": {"prompt_tokens": 500, "completion_tokens": 2048, "total_tokens": 2548},
        },
        # Turn 1 attempt 1: clean parallel recon + GraphQL tool calls
        {
            "index": 2,
            "turn": 1,
            "call_kind": "turn",
            "truncation_attempt": 1,
            "network_attempt": 0,
            "request": {
                "model": "openai/qwen3.8-27b",
                "messages": [
                    {"role": "system", "content": "Target: example.com.br"},
                    {"role": "user", "content": "Begin the engagement against: example.com.br"},
                    {"role": "user", "content": "## Known Facts\n(none)"},
                ],
                "tools": [{"type": "function", "function": {"name": "graphql_introspect"}}],
            },
            "duration_seconds": 6.2,
            "timestamp": "2026-11-07T01:00:05+00:00",
            "content": "",
            "reasoning_content": "Enumerating subdomains and probing GraphQL introspection on admin.example.com.br (192.0.2.10).",
            "tool_call_names": ["subfinder", "graphql_introspect"],
            "tool_calls": tc_turn1,
            "finish_reason": "tool_calls",
            "usage": {"prompt_tokens": 500, "completion_tokens": 120, "total_tokens": 620},
        },
        # Turn 2: logs finding #2 that gets retracted later
        {
            "index": 3,
            "turn": 2,
            "call_kind": "turn",
            "truncation_attempt": 0,
            "network_attempt": 0,
            "request": {
                "model": "openai/qwen3.8-27b",
                "messages": [
                    {"role": "system", "content": "Target: example.com.br"},
                    {"role": "user", "content": "Begin the engagement against: example.com.br"},
                    {"role": "assistant", "content": "", "tool_calls": tc_turn1},
                    {
                        "role": "tool",
                        "tool_call_id": "call_sub_1",
                        "content": json.dumps({"subdomains": ["admin.example.com.br"]}),
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
                    {"role": "user", "content": "## Known Facts\nadmin.example.com.br:443 service=https"},
                ],
                "tools": [{"type": "function", "function": {"name": "log_finding"}}],
            },
            "duration_seconds": 3.5,
            "timestamp": "2026-11-07T01:00:15+00:00",
            "content": "",
            "reasoning_content": "Logging suspected open redirect before verifying.",
            "tool_call_names": ["log_finding"],
            "tool_calls": tc_turn2_retracted,
            "finish_reason": "tool_calls",
            "usage": {"prompt_tokens": 700, "completion_tokens": 80, "total_tokens": 780},
        },
        # Turn 3: calls unknown tool
        {
            "index": 4,
            "turn": 3,
            "call_kind": "turn",
            "truncation_attempt": 0,
            "network_attempt": 0,
            "request": {
                "model": "openai/qwen3.8-27b",
                "messages": [
                    {"role": "system", "content": "Target: example.com.br"},
                    {"role": "assistant", "content": "", "tool_calls": tc_turn2_retracted},
                    {
                        "role": "tool",
                        "tool_call_id": "call_find_2",
                        "content": json.dumps({"logged": "finding", "finding_id": 2}),
                    },
                    {"role": "user", "content": "## Known Facts\nadmin.example.com.br:443 service=https"},
                ],
                "tools": [],
            },
            "duration_seconds": 2.1,
            "timestamp": "2026-11-07T01:00:20+00:00",
            "content": "",
            "reasoning_content": "Trying unknown scanner.",
            "tool_call_names": ["nonexistent_scanner"],
            "tool_calls": tc_turn3_bad_tool,
            "finish_reason": "tool_calls",
            "usage": {"prompt_tokens": 750, "completion_tokens": 50, "total_tokens": 800},
        },
        # Turn 4: premature stop (gets nudged in turn 5)
        {
            "index": 5,
            "turn": 4,
            "call_kind": "turn",
            "truncation_attempt": 0,
            "network_attempt": 0,
            "request": {
                "model": "openai/qwen3.8-27b",
                "messages": [
                    {"role": "system", "content": "Target: example.com.br"},
                    {"role": "assistant", "content": "", "tool_calls": tc_turn3_bad_tool},
                    {
                        "role": "tool",
                        "tool_call_id": "call_bad_3",
                        "content": json.dumps({"error": "unknown tool 'nonexistent_scanner'"}),
                    },
                    {"role": "user", "content": "## Known Facts\nadmin.example.com.br:443 arjun_params_discovered=['id']"},
                ],
                "tools": [{"type": "function", "function": {"name": "sqlmap_scan"}}],
            },
            "duration_seconds": 3.0,
            "timestamp": "2026-11-07T01:00:25+00:00",
            "content": "Final report: finished early.",
            "reasoning_content": "Wrapping up now.",
            "tool_call_names": [],
            "tool_calls": [],
            "finish_reason": "stop",
            "usage": {"prompt_tokens": 800, "completion_tokens": 40, "total_tokens": 840},
        },
        # Turn 5: post-nudge continuation with evidence_hydration + pivot_on_lead + parallel_batching
        {
            "index": 6,
            "turn": 5,
            "call_kind": "turn",
            "truncation_attempt": 0,
            "network_attempt": 0,
            "request": {
                "model": "openai/qwen3.8-27b",
                "messages": [
                    {"role": "system", "content": "Target: example.com.br"},
                    {"role": "assistant", "content": "Final report: finished early."},
                    {
                        "role": "user",
                        "content": "Before finalizing: FACTS shows at least one host:port with discovered parameters...",
                    },
                    {"role": "user", "content": "## Known Facts\nadmin.example.com.br:443 arjun_params_discovered=['id']"},
                ],
                "tools": [{"type": "function", "function": {"name": "sqlmap_scan"}}],
            },
            "duration_seconds": 5.0,
            "timestamp": "2026-11-07T01:00:30+00:00",
            "content": "",
            "reasoning_content": "Hydrating GraphQL evidence and testing discovered parameter 'id' on admin.example.com.br.",
            "tool_call_names": ["read_evidence", "sqlmap_scan"],
            "tool_calls": tc_turn5_post_nudge,
            "finish_reason": "tool_calls",
            "usage": {"prompt_tokens": 880, "completion_tokens": 90, "total_tokens": 970},
        },
        # Turn 6: clean final stop (no reasoning_content on this turn to test --require-reasoning)
        {
            "index": 7,
            "turn": 6,
            "call_kind": "turn",
            "truncation_attempt": 0,
            "network_attempt": 0,
            "request": {
                "model": "openai/qwen3.8-27b",
                "messages": [
                    {"role": "system", "content": "Target: example.com.br"},
                    {"role": "assistant", "content": "", "tool_calls": tc_turn5_post_nudge},
                    {
                        "role": "tool",
                        "tool_call_id": "call_read_ev_5",
                        "content": json.dumps({"types": ["Query", "Mutation"]}),
                    },
                    {
                        "role": "tool",
                        "tool_call_id": "call_sqli_5",
                        "content": json.dumps({"vulnerable": False}),
                    },
                    {"role": "user", "content": "## Known Facts\nadmin.example.com.br:443 sqli_tested=True"},
                ],
                "tools": [],
            },
            "duration_seconds": 4.1,
            "timestamp": "2026-11-07T01:00:40+00:00",
            "content": "# Executive Summary\nAssessment of example.com.br complete.",
            "reasoning_content": "",
            "tool_call_names": [],
            "tool_calls": [],
            "finish_reason": "stop",
            "usage": {"prompt_tokens": 950, "completion_tokens": 110, "total_tokens": 1060},
        },
    ]


class TestDatasetExporter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home = Path(self.temp_dir.name)
        self.target = "example.com.br"
        self.run_id, self.run_dir = create_run_dir(
            self.target, run_id="20261107T010000Z_ds01", tradecraft_home=self.home
        )
        self.target_dir = self.home / "targets" / self.target

        create_initial_manifest(
            run_dir=self.run_dir,
            run_id=self.run_id,
            target=self.target,
            model="openai/qwen3.8-27b",
            max_turns=10,
            profile="web",
        )
        finalize_manifest(self.run_dir, turns_used=6, findings_count=1)
        (self.run_dir / "log.txt").write_text(SAMPLE_LOG, encoding="utf-8")
        (self.run_dir / "facts.json").write_text(json.dumps(SAMPLE_FACTS, indent=2), encoding="utf-8")

        with open(self.run_dir / "trace.jsonl", "w", encoding="utf-8") as f:
            for rec in _make_trace_records():
                f.write(json.dumps(rec) + "\n")

        update_latest_symlink(self.target_dir, self.run_id)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_normalize_dataset_formats_and_behaviors(self):
        self.assertEqual(normalize_dataset_formats(None), ["sft"])
        self.assertEqual(normalize_dataset_formats("sft,dpo"), ["sft", "dpo"])
        self.assertEqual(normalize_dataset_formats("all"), ["sft", "dpo"])
        self.assertEqual(normalize_dataset_formats("checklist"), ["checklist"])
        with self.assertRaises(ValueError):
            normalize_dataset_formats("parquet")

        self.assertEqual(
            normalize_behaviors("recon_breadth,evidence_hydration"),
            ["recon_breadth", "evidence_hydration"],
        )
        with self.assertRaises(ValueError):
            normalize_behaviors("nonexistent_behavior")

    def test_resolve_dataset_run_dirs_modes(self):
        # 1. Explicit --run-dir
        dirs = resolve_dataset_run_dirs(run_dir=self.run_dir, tradecraft_home=self.home)
        self.assertEqual(dirs, [self.run_dir.resolve()])

        # 2. --target (defaults to latest)
        dirs_latest = resolve_dataset_run_dirs(target=self.target, tradecraft_home=self.home)
        self.assertEqual(dirs_latest, [self.run_dir.resolve()])

        # 3. --all across all targets
        dirs_all = resolve_dataset_run_dirs(all_runs=True, tradecraft_home=self.home)
        self.assertEqual(dirs_all, [self.run_dir.resolve()])

    def test_sft_quality_filtering_and_require_reasoning(self):
        source = load_run_dataset_source(self.run_dir)

        # Filtered (default):
        # - Turn 1 kept (clean retry)
        # - Turn 2 dropped (retracted finding #2)
        # - Turn 3 dropped (unknown tool dispatch error)
        # - Turn 4 dropped (premature stop that triggered a nudge in Turn 5)
        # - Turn 5 kept (post-nudge tool call)
        # - Turn 6 kept (clean final stop)
        filtered = extract_sft_records(source, filter_quality=True)
        self.assertEqual([r["turn"] for r in filtered], [1, 5, 6])
        self.assertEqual(
            filtered[0]["messages"][-1]["tool_calls"][0]["function"]["name"],
            "subfinder",
        )

        # With require_reasoning=True, Turn 6 (empty reasoning_content) is also excluded
        reasoning_only = extract_sft_records(source, filter_quality=True, require_reasoning=True)
        self.assertEqual([r["turn"] for r in reasoning_only], [1, 5])

        # Unfiltered: all 6 turns' winning completions are kept
        unfiltered = extract_sft_records(source, filter_quality=False)
        self.assertEqual([r["turn"] for r in unfiltered], [1, 2, 3, 4, 5, 6])

    def test_behavior_tagging_and_score_filtering(self):
        source = load_run_dataset_source(self.run_dir)
        records = extract_sft_records(source, filter_quality=True)

        # Turn 1 has recon_breadth + parallel_batching + fact_delta=1 -> score = 1 + 2(fact_delta) + 1(parallel) = 4
        t1_meta = records[0]["metadata"]
        self.assertIn("recon_breadth", t1_meta["behaviors"])
        self.assertIn("parallel_batching", t1_meta["behaviors"])
        self.assertEqual(t1_meta["fact_delta"], 1)
        self.assertGreaterEqual(t1_meta["score"], 4)
        self.assertEqual(t1_meta["profile"], "web")
        self.assertIsNone(t1_meta["guidance"])

        # Turn 5 has evidence_hydration + pivot_on_lead + parallel_batching + fact_delta=1 -> score >= 6
        t5_meta = records[1]["metadata"]
        self.assertIn("evidence_hydration", t5_meta["behaviors"])
        self.assertIn("pivot_on_lead", t5_meta["behaviors"])
        self.assertIn("parallel_batching", t5_meta["behaviors"])

        hydrated_only = extract_sft_records(source, behaviors="evidence_hydration")
        self.assertEqual([r["turn"] for r in hydrated_only], [5])

        high_score_only = extract_sft_records(source, min_score=5)
        self.assertEqual([r["turn"] for r in high_score_only], [5])

    def test_redundant_tool_call_filtered_in_sft_and_paired_in_dpo(self):
        source = load_run_dataset_source(self.run_dir)
        # Inject a duplicate turn repeating Turn 1's exact tool calls before Turn 5
        dup_call = dict(source.trace_records[1])
        dup_call["index"] = 99
        dup_call["turn"] = 1
        dup_call["call_kind"] = "turn_dup"
        source.trace_records.insert(2, dup_call)

        sft = extract_sft_records(source, filter_quality=True)
        # The duplicate turn_dup is excluded from SFT
        self.assertNotIn("turn_dup", [r["call_kind"] for r in sft])

        dpo = extract_dpo_records(source)
        reasons = [pair["reason"] for pair in dpo]
        self.assertIn("redundant_tool_call", reasons)

    def test_evaluate_run_checklist_and_profile_filtering(self):
        source = load_run_dataset_source(self.run_dir)
        checklist = evaluate_run_checklist(source)

        self.assertEqual(checklist["run_id"], self.run_id)
        self.assertEqual(checklist["profile"], "web")
        self.assertIsNone(checklist["guidance"])
        self.assertTrue(checklist["checks"]["clean_completion"])
        self.assertTrue(checklist["checks"]["tool_provenance_recorded"])
        self.assertTrue(checklist["checks"]["recon_breadth"])
        self.assertTrue(checklist["checks"]["evidence_hydration"])
        self.assertEqual(checklist["check_statuses"]["seed_respect"], "N/A")
        self.assertEqual(checklist["check_statuses"]["interactsh_polled"], "N/A")
        self.assertIn("context_management", checklist["scores"])
        self.assertIn("overall_score", checklist)
        self.assertTrue(checklist["diagnostics"])
        # Because SAMPLE_LOG has a retracted and an unverified finding, evidence_discipline is False
        self.assertFalse(checklist["checks"]["evidence_discipline"])
        self.assertFalse(checklist["passed"])

        # Profile filter matching 'web' includes the run; 'kubernetes' excludes it
        ds_web = build_datasets_from_sources([source], formats="sft,checklist", profiles="web")
        self.assertEqual(len(ds_web["sft"]), 3)
        self.assertEqual(len(ds_web["checklist"]), 1)

        ds_k8s = build_datasets_from_sources([source], formats="sft", profiles="kubernetes")
        self.assertEqual(len(ds_k8s["sft"]), 0)

    def test_report_confabulation_and_complement_seed_respect(self):
        source = load_run_dataset_source(self.run_dir)
        # Inject an unbacked CVE and unbacked subdomain into the final report turn
        source.trace_records[-1]["content"] = (
            "# Report\nConfirmed CVE-2099-99999 on phantom.example.com.br."
        )
        source.manifest["mode"] = "complement"

        checklist = evaluate_run_checklist(source)
        self.assertEqual(checklist["check_statuses"]["no_report_confabulation"], "FAIL")
        self.assertIn("CVE-2099-99999", checklist["metrics"]["unbacked_report_entities"])
        self.assertIn("phantom.example.com.br", checklist["metrics"]["unbacked_report_entities"])
        # Turn 1 ran subfinder + graphql_introspect (not exclusively baseline subfinder), so seed_respect is PASS
        self.assertEqual(checklist["check_statuses"]["seed_respect"], "PASS")

        # Confabulated final report turn (Turn 6) is dropped from SFT when filter_quality=True
        sft = extract_sft_records(source, filter_quality=True)
        self.assertNotIn(6, [r["turn"] for r in sft])

    def test_checklist_surfaces_guidance_from_manifest(self):
        source = load_run_dataset_source(self.run_dir)
        source.manifest["guidance"] = "Focus on the login flow."
        checklist = evaluate_run_checklist(source)
        self.assertEqual(checklist["guidance"], "Focus on the login flow.")

    def test_seed_respect_also_triggers_for_auto_seeded_runs_without_complement_mode(self):
        source = load_run_dataset_source(self.run_dir)
        # No --seed-from and mode stays "fresh" -- but the system prompt
        # carries an auto-injected cross-engagement seed block, which should
        # be enough on its own to turn seed_respect on.
        source.trace_records[0]["request"]["messages"][0]["content"] = (
            "Target: example.com.br\n\n--- Cross-engagement memory for root domain "
            "'example.com.br' ---\nPrior verified findings across this domain:\n"
            "- [admin.example.com.br | run x] FINDING: exposed admin panel\n---"
        )
        checklist = evaluate_run_checklist(source)
        # Turn 1 ran subfinder + graphql_introspect (not exclusively baseline
        # subfinder), so seed_respect is PASS -- the point here is it's no
        # longer N/A despite mode staying "fresh" and no seed_from set.
        self.assertEqual(checklist["check_statuses"]["seed_respect"], "PASS")

    def test_dpo_extracts_all_three_contrast_pair_types(self):
        source = load_run_dataset_source(self.run_dir)
        dpo = extract_dpo_records(source)

        reasons = [pair["reason"] for pair in dpo]
        self.assertEqual(reasons, ["truncation_retry", "retracted_finding", "open_thread_nudge"])

        # Check retracted_finding pair rewrites log_finding -> log_note in chosen
        retracted_pair = dpo[1]
        self.assertEqual(retracted_pair["turn"], 2)
        self.assertEqual(
            retracted_pair["rejected"]["tool_calls"][0]["function"]["name"],
            "log_finding",
        )
        self.assertEqual(
            retracted_pair["chosen"]["tool_calls"][0]["function"]["name"],
            "log_note",
        )

        # Check open_thread_nudge pair has premature stop in rejected and sqlmap_scan in chosen
        nudge_pair = dpo[2]
        self.assertEqual(nudge_pair["turn"], 4)
        self.assertNotIn("tool_calls", nudge_pair["rejected"])
        self.assertEqual(
            nudge_pair["chosen"]["tool_calls"][0]["function"]["name"],
            "read_evidence",
        )

    def test_scrub_anonymizes_domains_subdomains_and_ips(self):
        source = load_run_dataset_source(self.run_dir)
        sft_scrubbed = extract_sft_records(source, scrub=True)
        serialized = json.dumps(sft_scrubbed)

        self.assertNotIn("example.com.br", serialized)
        self.assertNotIn("192.0.2.10", serialized)
        self.assertIn("target.example", serialized)
        self.assertIn("sub1.target.example", serialized)
        self.assertIn("198.51.100.1", serialized)

    def test_cli_dataset_subcommand_writes_files(self):
        out_dir = self.home / "exported"
        cli_main([
            "dataset",
            "--run-dir", str(self.run_dir),
            "--format", "sft,dpo,checklist",
            "--profile", "web",
            "--behavior", "recon_breadth,evidence_hydration",
            "--scrub",
            "--output", str(out_dir),
        ])

        sft_path = out_dir / "dataset_sft.jsonl"
        dpo_path = out_dir / "dataset_dpo.jsonl"
        checklist_path = out_dir / "dataset_checklist.jsonl"
        self.assertTrue(sft_path.is_file())
        self.assertTrue(dpo_path.is_file())
        self.assertTrue(checklist_path.is_file())

        sft_lines = sft_path.read_text(encoding="utf-8").strip().splitlines()
        dpo_lines = dpo_path.read_text(encoding="utf-8").strip().splitlines()
        checklist_lines = checklist_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(sft_lines), 2)  # Turns 1 and 5 match recon_breadth / evidence_hydration
        self.assertEqual(len(dpo_lines), 3)
        self.assertEqual(len(checklist_lines), 1)
        self.assertNotIn("example.com.br", sft_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
