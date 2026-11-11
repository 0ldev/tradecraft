from unittest.mock import patch

from tradecraft.tools.dork_search_probe import DorkSearchProbe


def _sample_result():
    return {
        "query": "site:example.com filetype:pdf",
        "result_count": 1,
        "total_results_reported": "1",
        "results": [{"title": "Doc", "url": "https://example.com/a.pdf", "snippet": "s"}],
        "error": None,
    }


def test_extract_facts_with_site_operator():
    tool = DorkSearchProbe()
    facts = tool.extract_facts({"query": "site:example.com filetype:pdf"}, _sample_result())
    assert len(facts) == 1
    assert facts[0]["host"] == "example.com"
    assert facts[0]["port"] == 0
    assert facts[0]["dork_results_found"] == 1


def test_extract_facts_without_site_operator_returns_empty():
    tool = DorkSearchProbe()
    facts = tool.extract_facts({"query": 'intitle:"index of"'}, _sample_result())
    assert facts == []


def test_extract_facts_zero_results_returns_empty():
    tool = DorkSearchProbe()
    empty = {"query": "site:example.com", "result_count": 0, "results": [], "error": None}
    assert tool.extract_facts({"query": "site:example.com"}, empty) == []


def test_extract_evidence_with_site_operator():
    tool = DorkSearchProbe()
    result = _sample_result()
    full = {"query": "site:example.com filetype:pdf", "results": result["results"]}
    result["_full_evidence"] = full
    key, data = tool.extract_evidence({"query": "site:example.com filetype:pdf"}, result)
    assert key == "example.com"
    assert data == full
    assert "_full_evidence" not in result


def test_extract_evidence_without_site_operator_falls_back_to_query():
    tool = DorkSearchProbe()
    query = 'intitle:"index of"'
    result = {"query": query, "result_count": 0, "results": [], "error": None}
    # Simulate run() having attached _full_evidence
    result["_full_evidence"] = {"query": query, "results": []}
    key, data = tool.extract_evidence({"query": query}, result)
    assert key == query
    assert data == {"query": query, "results": []}
    assert "_full_evidence" not in result


def test_run_passes_params_through_to_adapter():
    tool = DorkSearchProbe()
    with patch("tradecraft.tools.dork_search_probe.dork_execute.execute") as mock_exec:
        mock_exec.return_value = type("Raw", (), {"query": "site:example.com", "items": [], "total_results_reported": "0", "error": None})()
        res = tool.run(query="site:example.com", num_results=5, timeout=7)
    mock_exec.assert_called_once_with(query="site:example.com", num_results=5, timeout=7)
    assert res["result_count"] == 0
    assert "_full_evidence" in res
