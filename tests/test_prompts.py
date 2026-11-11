import unittest
from unittest import mock

from tradecraft.execution.prompts import build_state_message, build_system_prompt
from tradecraft.skills.loader import render_skills


class TestSystemPrompt(unittest.TestCase):
    def test_system_prompt_renders_target_and_no_placeholders(self):
        prompt = build_system_prompt("example.com")
        self.assertTrue(prompt.startswith("# Tradecraft\n"))
        self.assertIn("## Target\n\nexample.com", prompt)
        for placeholder in ("{target}", "{skills}", "{rules_extra}", "{seed_context}", "{guidance}"):
            self.assertNotIn(placeholder, prompt)

    def test_system_prompt_without_guidance_omits_guidance_block(self):
        prompt = build_system_prompt("example.com")
        self.assertNotIn("## Operator Guidance", prompt)

    def test_system_prompt_has_no_dynamic_state_sections(self):
        # The state (log, facts, budget) must NOT live in the static system
        # prompt -- that is what keeps it byte-identical across turns.
        prompt = build_system_prompt("example.com")
        self.assertNotIn("## Engagement Log So Far", prompt)
        self.assertNotIn("## Known Facts", prompt)
        self.assertNotIn("## Engagement Budget", prompt)

    def test_system_prompt_is_identical_across_calls(self):
        # Same inputs must give the same bytes every turn (cache prefix).
        self.assertEqual(
            build_system_prompt("example.com", allowed_tools=["nmap_scan"]),
            build_system_prompt("example.com", allowed_tools=["nmap_scan"]),
        )

    def test_system_prompt_with_seed_context_injects_prior_context_block(self):
        seed_ctx = "--- Known from a prior engagement (run 20261101T100000Z_000001) ---\nPrior facts: example.com:22"
        prompt = build_system_prompt("example.com", seed_context=seed_ctx)
        self.assertIn("## Prior Engagement Context", prompt)
        self.assertIn("Prior facts: example.com:22", prompt)
        self.assertNotIn("{seed_context}", prompt)

    def test_system_prompt_with_guidance_injects_advisory_block(self):
        prompt = build_system_prompt("example.com", guidance="Focus on the login flow.")
        self.assertIn("## Operator Guidance", prompt)
        self.assertIn("Focus on the login flow.", prompt)
        self.assertIn("still log it via `log_finding`", prompt)
        self.assertNotIn("{guidance}", prompt)

    def test_system_prompt_blank_guidance_omits_guidance_block(self):
        prompt = build_system_prompt("example.com", guidance="   ")
        self.assertNotIn("## Operator Guidance", prompt)

    def test_system_prompt_guidance_appears_between_target_and_tradecraft(self):
        seed_ctx = "--- Known from a prior engagement (run x) ---\nfacts"
        prompt = build_system_prompt(
            "example.com", seed_context=seed_ctx, guidance="Avoid the /admin panel."
        )
        idx_target = prompt.index("## Target")
        idx_guidance = prompt.index("## Operator Guidance")
        idx_seed = prompt.index("## Prior Engagement Context")
        idx_tradecraft = prompt.index("## Tradecraft Knowledge")
        self.assertTrue(idx_target < idx_guidance < idx_seed < idx_tradecraft)

    def test_system_prompt_with_allowed_tools_injects_restriction_rule(self):
        prompt = build_system_prompt("example.com", allowed_tools=["nmap_scan", "httpx_probe"])
        self.assertIn("Active tools for this engagement are restricted by operator policy", prompt)
        self.assertIn("['httpx_probe', 'nmap_scan']", prompt)
        self.assertIn("UNAVAILABLE and must not be called", prompt)

    def test_system_prompt_without_allowed_tools_omits_restriction_rule(self):
        prompt = build_system_prompt("example.com", allowed_tools=None)
        self.assertNotIn("Active tools for this engagement are restricted by operator policy", prompt)

    def test_system_prompt_includes_skills(self):
        skills = render_skills()
        self.assertIn("### evidence retrieval", skills)
        self.assertIn("### js endpoint extraction", skills)
        self.assertIn("When multiple subdomains serve variants or staging builds", skills)
        prompt = build_system_prompt("example.com")
        self.assertIn("### evidence retrieval", prompt)
        self.assertIn("Call `log_finding` immediately once a vulnerability or security finding is", prompt)

    def test_system_prompt_fallback_when_no_skills(self):
        with unittest.mock.patch("pathlib.Path.glob", return_value=[]):
            self.assertEqual(render_skills(), "(no skills loaded)")


class TestStateMessage(unittest.TestCase):
    def test_state_message_carries_log_facts_and_budget(self):
        msg = build_state_message(
            "- [note] checked login page",
            "example.com:443 open",
            "Turn 5 of 10 (5 remaining). No conversation trimming has happened yet.",
        )
        self.assertIn("## Engagement Log So Far", msg)
        self.assertIn("- [note] checked login page", msg)
        self.assertIn("## Known Facts", msg)
        self.assertIn("example.com:443 open", msg)
        self.assertIn("## Engagement Budget", msg)
        self.assertIn("Turn 5 of 10 (5 remaining).", msg)

    def test_state_message_labels_itself_as_harness_context(self):
        msg = build_state_message("(no notes yet)")
        self.assertIn("not a message from the operator", msg)

    def test_state_message_defaults(self):
        msg = build_state_message("(no notes yet)")
        self.assertIn("(no facts recorded yet)", msg)
        self.assertIn("(not yet computed)", msg)
