from __future__ import annotations

from unittest.mock import patch

import pytest

from tradecraft.tools.interactsh import Interactsh


class TestInteractshTool:
    @pytest.fixture
    def tool(self):
        return Interactsh()

    @patch("tradecraft.tools.interactsh.run_interactsh")
    def test_run_generate(self, mock_run, tool):
        mock_run.return_value = {
            "action": "generate",
            "active": True,
            "payload_domain": "abc123xyz.oast.me",
            "payload_url": "http://abc123xyz.oast.me",
        }
        res = tool.run(action="generate")
        assert res["active"] is True
        assert res["payload_domain"] == "abc123xyz.oast.me"

    @patch("tradecraft.tools.interactsh.run_interactsh")
    def test_run_poll_with_truncation(self, mock_run, tool):
        fake_interactions = [
            {"protocol": "dns", "remote_address": f"10.0.0.{i}", "request_summary": "DNS query"}
            for i in range(15)
        ]
        mock_run.return_value = {
            "action": "poll",
            "active": True,
            "payload_domain": "abc123xyz.oast.me",
            "total_interactions": 15,
            "interactions": fake_interactions,
        }
        res = tool.run(action="poll")
        assert res["total_interactions"] == 15
        assert len(res["interactions"]) == 10
        assert res["omitted_interactions"] == 5
        assert "_full_evidence" in res
        assert res["_full_evidence"]["total_interactions"] == 15

    def test_extract_evidence(self, tool):
        result = {
            "action": "poll",
            "payload_domain": "abc123xyz.oast.me",
            "_full_evidence": {
                "payload_domain": "abc123xyz.oast.me",
                "total_interactions": 1,
            },
        }
        ev = tool.extract_evidence({"action": "poll"}, result)
        assert ev is not None
        domain, full = ev
        assert domain == "abc123xyz.oast.me"
        assert full["total_interactions"] == 1
        assert "_full_evidence" not in result

    def test_extract_facts(self, tool):
        result = {
            "interactions": [
                {"protocol": "http", "remote_address": "203.0.113.41:44321", "after_domain_generated": True},
            ],
            "evidence_id": "interactsh:abc123xyz.oast.me",
        }
        facts = tool.extract_facts({"action": "poll"}, result)
        assert len(facts) == 1
        assert facts[0]["host"] == "203.0.113.41"
        assert facts[0]["oast_interaction_detected"] is True
        assert facts[0]["oast_protocol"] == "http"
        assert facts[0]["evidence"] == "interactsh:abc123xyz.oast.me"

    def test_extract_facts_excludes_stale_interaction(self, tool):
        result = {
            "interactions": [
                {"protocol": "http", "remote_address": "203.0.113.41:44321", "after_domain_generated": False},
            ],
            "evidence_id": "interactsh:abc123xyz.oast.me",
        }
        assert tool.extract_facts({"action": "poll"}, result) == []

    def test_extract_facts_keeps_interaction_with_unknown_timing(self, tool):
        # after_domain_generated is None (unparseable timestamp) --
        # absence of proof isn't proof of staleness, so this must
        # still be recorded.
        result = {
            "interactions": [
                {"protocol": "http", "remote_address": "203.0.113.41:44321", "after_domain_generated": None},
            ],
            "evidence_id": "interactsh:abc123xyz.oast.me",
        }
        facts = tool.extract_facts({"action": "poll"}, result)
        assert len(facts) == 1
        assert facts[0]["oast_interaction_detected"] is True
