from unittest.mock import patch

from tradecraft.adapters.spa_crawl.execute import RawSpaCrawlResult
from tradecraft.tools.spa_crawl import SpaCrawl


def test_spa_crawl_availability():
    tool = SpaCrawl()
    assert isinstance(tool.is_available(), bool)


def test_spa_crawl_run_error():
    tool = SpaCrawl()
    with patch("tradecraft.tools.spa_crawl.spa_execute") as mock_exec:
        mock_exec.return_value = RawSpaCrawlResult(
            error="DNS resolution failed",
        )
        res = tool.run(target_url="https://example.com/spa")
        assert res["target"] == "https://example.com/spa"
        assert res["target_url"] == "https://example.com/spa"
        assert res["error"] == "DNS resolution failed"


def test_spa_crawl_run_success():
    tool = SpaCrawl()
    with patch("tradecraft.tools.spa_crawl.spa_execute") as mock_exec:
        mock_exec.return_value = RawSpaCrawlResult(
            final_url="https://example.com/spa/dashboard",
            requests=[
                {"method": "GET", "url": "https://example.com/api/v1/user"},
                {"method": "POST", "url": "https://example.com/api/v1/update", "json_params": ["name"]},
            ],
        )

        res = tool.run(target_url="https://example.com/spa")
        assert res["target"] == "https://example.com/spa"
        assert res["target_url"] == "https://example.com/spa"
        assert res["final_url"] == "https://example.com/spa/dashboard"
        assert res["total_requests"] == 2
        assert len(res["requests"]) == 2

        facts = tool.extract_facts({"target_url": "https://example.com/spa"}, res)
        assert facts == []

        evidence = tool.extract_evidence({"target_url": "https://example.com/spa"}, res)
        assert evidence is not None
        assert evidence[0] == "https://example.com/spa"
