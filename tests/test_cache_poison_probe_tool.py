from unittest.mock import patch

from tradecraft.adapters.cache_poison_probe.execute import PoisonAttempt
from tradecraft.tools.cache_poison_probe import CachePoisonProbe


def test_cache_poison_probe_tool_vulnerable():
    tool = CachePoisonProbe()
    attempts = [
        PoisonAttempt(
            header_name="X-Forwarded-Host",
            marker_value="cp1.attacker-controlled.test",
            poison_status=200,
            clean_status=200,
            attempted_clean=True,
            clean_body="hello cp1.attacker-controlled.test world",
        ),
        PoisonAttempt(
            header_name="X-Host",
            marker_value="cp2.attacker-controlled.test",
            poison_status=200,
            clean_status=200,
            attempted_clean=True,
            clean_body="clean response",
        ),
    ]

    with patch("tradecraft.tools.cache_poison_probe.cp_execute.execute", return_value=attempts):
        res = tool.run("https://cdn.example.com/blog")
        assert res["target"] == "https://cdn.example.com/blog"
        assert res["vulnerable"] is True
        assert res["vulnerable_headers"] == ["X-Forwarded-Host"]

        facts = tool.extract_facts({"target": "https://cdn.example.com/blog"}, res)
        assert facts == [{
            "host": "cdn.example.com",
            "port": 443,
            "cache_poisoning": "vulnerable via X-Forwarded-Host",
        }]

        # Evidence extraction
        canonical, full = tool.extract_evidence({"target": "https://cdn.example.com/blog"}, res)
        assert canonical == "cdn.example.com"
        assert full["vulnerable"] is True
        assert len(full["attempts"]) == 2


def test_cache_poison_probe_tool_not_vulnerable():
    tool = CachePoisonProbe()
    attempts = [
        PoisonAttempt(
            header_name="X-Forwarded-Host",
            marker_value="cp1.attacker-controlled.test",
            poison_status=200,
            attempted_clean=False,
        )
    ]

    with patch("tradecraft.tools.cache_poison_probe.cp_execute.execute", return_value=attempts):
        res = tool.run("https://example.com/page")
        assert res["vulnerable"] is False

        # Facts extraction returns empty list
        facts = tool.extract_facts({"target": "https://example.com/page"}, res)
        assert facts == []
