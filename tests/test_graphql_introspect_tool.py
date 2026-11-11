from unittest.mock import patch

from tradecraft.adapters.graphql_introspect.execute import RawGraphqlResult
from tradecraft.tools.graphql_introspect import GraphqlIntrospect


def test_graphql_introspect_tool_run_enabled():
    tool = GraphqlIntrospect()
    fake_body = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [{"name": "User"}, {"name": "Admin"}],
            }
        }
    }

    with patch("tradecraft.tools.graphql_introspect.graphql_execute.execute") as mock_exec:
        mock_exec.return_value = RawGraphqlResult(
            status_code=200,
            body=fake_body,
            error=None,
        )
        res = tool.run("https://api.example.com:8443/graphql")

        assert res["url"] == "https://api.example.com:8443/graphql"
        assert res["introspection_enabled"] is True
        assert res["type_count"] == 2
        assert res["sample_types"] == ["User", "Admin"]

        # Facts extraction: emits fact only when enabled
        facts = tool.extract_facts({"url": "https://api.example.com:8443/graphql"}, res)
        assert len(facts) == 1
        assert facts[0] == {
            "host": "api.example.com",
            "port": 8443,
            "graphql_introspection": "enabled",
            "graphql_type_count": 2,
        }

        # Evidence extraction keys off netloc
        canonical, full = tool.extract_evidence({"url": "https://api.example.com:8443/graphql"}, res)
        assert canonical == "api.example.com:8443"
        assert full["response"] == fake_body


def test_graphql_introspect_tool_run_disabled():
    tool = GraphqlIntrospect()
    with patch("tradecraft.tools.graphql_introspect.graphql_execute.execute") as mock_exec:
        mock_exec.return_value = RawGraphqlResult(
            status_code=200,
            body={"errors": [{"message": "Introspection disabled"}]},
            error=None,
        )
        res = tool.run("https://api.example.com/graphql")
        assert res["introspection_enabled"] is False

        # Facts extraction returns empty list when introspection is disabled
        facts = tool.extract_facts({"url": "https://api.example.com/graphql"}, res)
        assert facts == []
