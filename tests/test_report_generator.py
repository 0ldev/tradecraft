"""
Unit tests for the post-engagement report generator (tradecraft/reporting/generator.py).
"""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tradecraft.execution.loop import EngagementResult
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.facts import FactStore
from tradecraft.reporting.generator import (
    EXEC_SUMMARY_INPUT_CHAR_LIMIT,
    generate_executive_summary,
    generate_report,
    render_attack_surface_inventory,
    render_closing_notes,
    render_evidence_index,
    render_findings,
)

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
    {
        "host": "examplepaint.com.br",
        "port": 443,
        "evidence": "cloudenum:examplepaint",
    },
    {
        "host": "webmail.examplepaint.com.br",
        "port": 443,
        "http_status": 200,
        "http_title": "Webmail Locaweb : Faça o Login do Webmail Seguro",
        "evidence": "httpx_probe:webmail.examplepaint.com.br",
    },
]

REAL_CAPTURED_FINDINGS = [
    "Apex examplepaint.com.br (192.0.2.10) runs Apache + PHP 7.0.33 (end-of-life since Jan 2019) — detected via httpx_probe/whatweb. No WAF in front.",
    "cPanel login interface live at cpanel.examplepaint.com.br (200, 'cPanel Login', Apache). webdisk.examplepaint.com.br returns 401 (cPanel Basic auth file manager).",
    "Mail/DNS surface on 192.0.2.10: Exim 4.92 (465/587), Dovecot pop3d/imapd (110/143), imaps/pop3s (993/995), PowerDNS Authoritative 4.1.1 on 53.",
]


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.evidence_dir = Path(self.temp_dir.name) / "evidence"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_render_attack_surface_inventory_empty(self):
        facts = FactStore()
        rendered = render_attack_surface_inventory(facts)
        self.assertEqual(rendered, "_(no facts recorded for this engagement)_")

    def test_render_attack_surface_inventory_populated(self):
        facts = FactStore()
        for rec in REAL_CAPTURED_FACTS:
            h = rec["host"]
            p = rec["port"]
            attrs = {k: v for k, v in rec.items() if k not in ("host", "port")}
            facts.merge_port(h, p, attrs)

        rendered = render_attack_surface_inventory(facts)
        self.assertIn("| Host | Port | Details |", rendered)
        self.assertIn("|---|---|---|", rendered)
        self.assertIn("| materiais.examplepaint.com.br | 443 |", rendered)
        self.assertIn("http_status=404", rendered)
        self.assertIn("| examplepaint.com.br | 53 |", rendered)
        self.assertIn("dns_a=192.0.2.10", rendered)

    def test_render_findings_empty(self):
        rendered = render_findings([])
        self.assertEqual(rendered, "_(no findings logged)_")

    def test_render_findings_populated(self):
        rendered = render_findings(REAL_CAPTURED_FINDINGS)
        lines = rendered.splitlines()
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].startswith("- Apex examplepaint.com.br"))
        self.assertTrue(lines[1].startswith("- cPanel login"))
        self.assertTrue(lines[2].startswith("- Mail/DNS surface"))

    def test_render_closing_notes_empty(self):
        self.assertEqual(render_closing_notes(""), "> _(no closing notes)_")
        self.assertEqual(render_closing_notes("   \n  "), "> _(no closing notes)_")

    def test_render_closing_notes_populated(self):
        notes = "First conclusion line.\n\nSecond conclusion line."
        rendered = render_closing_notes(notes)
        lines = rendered.splitlines()
        self.assertEqual(lines[0], "> First conclusion line.")
        self.assertEqual(lines[1], ">")
        self.assertEqual(lines[2], "> Second conclusion line.")

    def test_render_evidence_index_empty(self):
        evidence = EvidenceStore(persist_dir=self.evidence_dir)
        self.assertEqual(render_evidence_index(evidence), "_(no evidence persisted for this run)_")

    def test_render_evidence_index_populated(self):
        evidence = EvidenceStore(persist_dir=self.evidence_dir)
        evidence.save("examplepaint.com.br", "dnsx", {"a": ["192.0.2.10"]})
        evidence.save("webmail.examplepaint.com.br", "httpx_probe", {"status_code": 200})

        rendered = render_evidence_index(evidence)
        lines = rendered.splitlines()
        self.assertIn("- `dnsx:examplepaint.com.br`", lines)
        self.assertIn("- `httpx_probe:webmail.examplepaint.com.br`", lines)

    def test_generate_report_refusal_when_no_facts_and_no_findings(self):
        result = EngagementResult(
            report="Nothing found.",
            findings=[],
            turns_used=1,
            facts=FactStore(),
            evidence=EvidenceStore(persist_dir=self.evidence_dir),
        )
        with mock.patch("litellm.completion") as mock_comp:
            report = generate_report(result, model="test-model")
            self.assertIsNone(report)
            mock_comp.assert_not_called()

    def test_generate_report_empty_model_raises_value_error(self):
        result = EngagementResult(report="", findings=["test"])
        with self.assertRaises(ValueError):
            generate_report(result, model="")

    @mock.patch("litellm.completion")
    def test_generate_report_success_structure(self, mock_comp):
        mock_choice = mock.MagicMock()
        mock_choice.message.content = "Executive summary of the engagement on examplepaint.com.br."
        mock_comp.return_value = mock.MagicMock(choices=[mock_choice])

        facts = FactStore()
        for rec in REAL_CAPTURED_FACTS:
            facts.merge_port(rec["host"], rec["port"], {k: v for k, v in rec.items() if k not in ("host", "port")})

        evidence = EvidenceStore(persist_dir=self.evidence_dir)
        evidence.save("examplepaint.com.br", "dnsx", {"a": ["192.0.2.10"]})

        result = EngagementResult(
            target="examplepaint.com.br",
            report="All testing completed thoroughly.",
            findings=REAL_CAPTURED_FINDINGS,
            turns_used=4,
            facts=facts,
            evidence=evidence,
        )

        report = generate_report(result, model="test-model")
        self.assertIsNotNone(report)
        self.assertIn("# Security Assessment Report: examplepaint.com.br", report)
        self.assertIn("engagement used 4 turn(s)", report)
        self.assertIn("## Executive Summary", report)
        self.assertIn("Executive summary of the engagement on examplepaint.com.br.", report)
        self.assertIn("## Attack Surface Inventory", report)
        self.assertIn("| Host | Port | Details |", report)
        self.assertIn("## Findings", report)
        self.assertIn("- Apex examplepaint.com.br", report)
        self.assertIn("## Model's Closing Notes", report)
        self.assertIn("> All testing completed thoroughly.", report)
        self.assertIn("## Evidence Index", report)
        self.assertIn("- `dnsx:examplepaint.com.br`", report)

        # Confirm litellm completion arguments
        mock_comp.assert_called_once()
        kwargs = mock_comp.call_args[1]
        self.assertEqual(kwargs["model"], "test-model")
        messages = kwargs["messages"]
        self.assertEqual(messages[0]["role"], "system")
        self.assertIn("--- Attack Surface Inventory ---", messages[0]["content"])
        self.assertIn("--- Findings ---", messages[0]["content"])
        self.assertEqual(messages[1]["role"], "user")
        self.assertEqual(messages[1]["content"], "Write the Executive Summary now.")

    @mock.patch("litellm.completion")
    def test_generate_report_chunking_fallback(self, mock_comp):
        long_finding = "A" * 1500
        findings = [f"Finding {i}: {long_finding}" for i in range(25)]

        # Responses for 2 map calls (batch 0..20, batch 20..25) + 1 reduce call
        map1 = mock.MagicMock(choices=[mock.MagicMock(message=mock.MagicMock(content="Summary batch 1"))])
        map2 = mock.MagicMock(choices=[mock.MagicMock(message=mock.MagicMock(content="Summary batch 2"))])
        reduce_resp = mock.MagicMock(choices=[mock.MagicMock(message=mock.MagicMock(content="Final reduced summary"))])
        mock_comp.side_effect = [map1, map2, reduce_resp]

        facts = FactStore()
        facts.merge_port("target.com", 80, {"service": "http"})
        result = EngagementResult(
            target="target.com",
            report="Done",
            findings=findings,
            turns_used=3,
            facts=facts,
            evidence=EvidenceStore(persist_dir=self.evidence_dir),
        )

        report = generate_report(result, model="test-model")
        self.assertIsNotNone(report)
        self.assertIn("Final reduced summary", report)
        self.assertEqual(mock_comp.call_count, 3)

        reduce_call_kwargs = mock_comp.call_args_list[2][1]
        reduce_sys_prompt = reduce_call_kwargs["messages"][0]["content"]
        self.assertIn("--- Findings Summary Bullets ---", reduce_sys_prompt)
        self.assertIn("Summary batch 1", reduce_sys_prompt)
        self.assertIn("Summary batch 2", reduce_sys_prompt)


if __name__ == "__main__":
    unittest.main()
