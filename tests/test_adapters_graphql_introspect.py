from unittest.mock import MagicMock, patch
import requests

from tradecraft.adapters.graphql_introspect import execute as graphql_execute
from tradecraft.adapters.graphql_introspect import parse as graphql_parse
from tradecraft.adapters.graphql_introspect.execute import RawGraphqlResult


def test_execute_empty_url():
    res = graphql_execute.execute("   ")
    assert res.error == "empty URL"


def test_execute_success():
    fake_body = {"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"name": "User"}]}}}
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"data": ...}'
    mock_resp.json.return_value = fake_body

    with patch("requests.post", return_value=mock_resp) as mock_post:
        res = graphql_execute.execute("https://api.example.com/graphql")
        assert res.error is None
        assert res.status_code == 200
        assert res.body == fake_body
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        assert "IntrospectionQuery" in call_kwargs["json"]["query"]


def test_execute_request_exception():
    with patch("requests.post", side_effect=requests.ConnectTimeout("Connection timed out")):
        res = graphql_execute.execute("https://api.example.com/graphql")
        assert res.status_code == 0
        assert res.body is None
        assert "timed out" in res.error


def test_parse_introspection_with_error():
    res = RawGraphqlResult(error="network failure")
    parsed = graphql_parse.parse_introspection(res)
    assert parsed["introspection_enabled"] is None
    assert parsed["error"] == "network failure"


def test_parse_introspection_enabled():
    res = RawGraphqlResult(
        status_code=200,
        body={
            "data": {
                "__schema": {
                    "queryType": {"name": "RootQueryType"},
                    "types": [
                        {"name": "Query", "kind": "OBJECT"},
                        {"name": "User", "kind": "OBJECT"},
                        {"name": "Order", "kind": "OBJECT"},
                    ],
                }
            }
        },
    )
    parsed = graphql_parse.parse_introspection(res)
    assert parsed["introspection_enabled"] is True
    assert parsed["query_type"] == "RootQueryType"
    assert parsed["type_count"] == 3
    assert parsed["sample_types"] == ["Query", "User", "Order"]


def test_parse_introspection_disabled_or_forbidden():
    res = RawGraphqlResult(
        status_code=400,
        body={"errors": [{"message": "GraphQL introspection is not allowed by policy"}]},
    )
    parsed = graphql_parse.parse_introspection(res)
    assert parsed["introspection_enabled"] is False
    assert parsed["errors"] == [{"message": "GraphQL introspection is not allowed by policy"}]
