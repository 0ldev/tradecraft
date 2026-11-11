import json
from unittest.mock import patch

from tradecraft.adapters.playwright_engine.execute import RawPlaywrightResult
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.tools.playwright_engine import PlaywrightEngine


def test_playwright_engine_availability():
    tool = PlaywrightEngine()
    # In an environment with playwright installed, is_available is True
    # or False depending on import
    assert isinstance(tool.is_available(), bool)


def test_playwright_engine_run_error():
    tool = PlaywrightEngine()
    with patch("tradecraft.tools.playwright_engine.pw_execute") as mock_exec:
        mock_exec.return_value = RawPlaywrightResult(
            error="Connection timed out",
        )
        res = tool.run(target_url="https://example.com", actions="[]")
        assert res["target_url"] == "https://example.com"
        assert res["error"] == "Connection timed out"


def test_playwright_engine_run_with_screenshot(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    tool = PlaywrightEngine(store=store)
    fake_png = b"\x89PNG\r\n\x1a\nplaywrightscreenshot"

    with patch("tradecraft.tools.playwright_engine.pw_execute") as mock_exec:
        mock_exec.return_value = RawPlaywrightResult(
            final_url="https://example.com/welcome",
            dom_findings=[{
                "path": "https://example.com/welcome",
                "sink_type": "innerHTML",
                "payload": "<b>rsxssprobe</b>",
            }],
            storage_keys=[{"storage_type": "localStorage", "key_name": "auth_token"}],
            screenshot_png=fake_png,
        )

        res = tool.run(
            target_url="https://example.com",
            actions=json.dumps([{"action": "wait", "value": 100}]),
            probe_xss=True,
        )

        assert res["target_url"] == "https://example.com"
        assert res["final_url"] == "https://example.com/welcome"
        assert len(res["dom_findings"]) == 1
        assert "screenshot_evidence_id" in res
        assert "screenshot saved to evidence storage" in res["note"]

        facts = tool.extract_facts({"target_url": "https://example.com"}, res)
        assert len(facts) == 1
        assert facts[0]["vulnerability"] == "DOM-based XSS (unescaped reflection confirmed via headless browser)"
        assert facts[0]["host"] == "example.com"
        assert facts[0]["port"] == 443

        evidence = tool.extract_evidence({"target_url": "https://example.com"}, res)
        assert evidence is not None
        assert evidence[0] == "https://example.com"


def test_playwright_engine_facts_empty_when_no_xss():
    tool = PlaywrightEngine()
    res = {
        "target_url": "https://example.com:8080",
        "dom_findings": [],
    }
    facts = tool.extract_facts({"target_url": "https://example.com:8080"}, res)
    assert facts == []
