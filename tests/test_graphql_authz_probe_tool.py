"""
Unit tests for GraphqlAuthzProbe tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.graphql_authz_probe.execute import FieldAuthzResult, GraphqlAuthzResult
from tradecraft.tools.graphql_authz_probe import GraphqlAuthzProbe


def _vuln_result():
    return GraphqlAuthzResult(
        target="https://api.example.com/graphql",
        fields_checked=[FieldAuthzResult(field_name="order", vulnerable=True, status="vulnerable")],
        vulnerable=True,
        summary="order: VULNERABLE",
    )


def test_run_returns_parsed_result():
    tool = GraphqlAuthzProbe()
    with patch("tradecraft.tools.graphql_authz_probe.authz_execute", return_value=_vuln_result()):
        out = tool.run("https://api.example.com/graphql", sample_id="123")
    assert out["vulnerable"] is True


def test_extract_facts_not_vulnerable_is_empty():
    tool = GraphqlAuthzProbe()
    assert tool.extract_facts({"target": "https://api.example.com/graphql"}, {"vulnerable": False}) == []


def test_extract_facts_vulnerable_is_high():
    tool = GraphqlAuthzProbe()
    res = {"vulnerable": True, "fields_checked": [{"field_name": "order", "vulnerable": True}]}
    facts = tool.extract_facts({"target": "https://api.example.com:8443/graphql"}, res)
    assert len(facts) == 1
    assert facts[0]["severity"] == "high"
    assert facts[0]["host"] == "api.example.com"
    assert facts[0]["port"] == 8443
    assert "order" in facts[0]["vulnerability"]
