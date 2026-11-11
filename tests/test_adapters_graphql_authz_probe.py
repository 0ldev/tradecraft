"""
Unit tests for graphql_authz_probe adapter (execution and parsing).
"""
import json
from unittest.mock import MagicMock, patch

from tradecraft.adapters.graphql_authz_probe.execute import (
    CandidateField,
    GraphqlAuthzResult,
    build_query,
    check_field_authz,
    execute,
    select_candidate_fields,
)
from tradecraft.adapters.graphql_authz_probe.parse import parse

SCHEMA = {
    "queryType": {
        "name": "Query",
        "fields": [
            {
                "name": "order",
                "args": [{"name": "orderId", "type": {"name": "ID", "kind": "SCALAR", "ofType": None}}],
                "type": {
                    "name": "Order", "kind": "OBJECT",
                    "fields": [
                        {"name": "id", "type": {"name": "ID"}},
                        {"name": "total", "type": {"name": "Float"}},
                        {"name": "email", "type": {"name": "String"}},
                    ],
                },
            },
            {
                "name": "search",
                "args": [{"name": "query", "type": {"name": "String"}}],
                "type": {"name": "SearchResult", "kind": "OBJECT", "fields": []},
            },
            {
                "name": "product",
                "args": [{"name": "productId", "type": {"name": "Int", "kind": "SCALAR", "ofType": None}}],
                "type": {"name": "Product", "kind": "OBJECT", "fields": [{"name": "name", "type": {"name": "String"}}]},
            },
        ],
    },
}


def _resp(status_code, payload):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = payload
    return r


def test_select_candidate_fields_prioritizes_lookup_names():
    candidates = select_candidate_fields(SCHEMA, max_fields=5)
    # 'order' has both an id-shaped arg and a lookup-shaped name --
    # prioritized ahead of 'product' (id-shaped arg, no lookup name).
    # 'search' has no id-shaped arg and is excluded entirely.
    names = [c.field_name for c in candidates]
    assert names == ["order", "product"]
    order_candidate = candidates[0]
    assert order_candidate.id_arg_name == "orderId"
    assert order_candidate.id_arg_type == "ID"
    assert set(order_candidate.scalar_fields) == {"id", "email"}  # 'total' isn't in SCALAR_FIELD_CANDIDATES


def test_build_query_quotes_non_numeric_arg_type():
    candidate = CandidateField(field_name="order", id_arg_name="orderId", id_arg_type="ID", scalar_fields=["id", "email"])
    q = build_query(candidate, "12345")
    assert q == 'query { order(orderId: "12345") { __typename id email } }'


def test_build_query_does_not_quote_int_arg_type():
    candidate = CandidateField(field_name="product", id_arg_name="productId", id_arg_type="Int", scalar_fields=["name"])
    q = build_query(candidate, "42")
    assert q == "query { product(productId: 42) { __typename name } }"


@patch("tradecraft.adapters.graphql_authz_probe.execute.requests.post")
def test_check_field_authz_vulnerable(mock_post):
    candidate = CandidateField(field_name="order", id_arg_name="orderId", id_arg_type="ID", scalar_fields=["email"])
    mock_post.side_effect = [
        _resp(200, {"data": {"order": {"__typename": "Order", "email": "victim@example.com"}}}),
        _resp(200, {"data": {"order": {"__typename": "Order", "email": "victim@example.com"}}}),
    ]
    res = check_field_authz(
        "https://api.example.com/graphql", candidate, "12345",
        headers_privileged="Authorization: Bearer real-token", headers_unauth=None, timeout=5.0,
    )
    assert res.baseline_resolved is True
    assert res.unauth_resolved is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"


@patch("tradecraft.adapters.graphql_authz_probe.execute.requests.post")
def test_check_field_authz_not_vulnerable(mock_post):
    candidate = CandidateField(field_name="order", id_arg_name="orderId", id_arg_type="ID", scalar_fields=["email"])
    mock_post.side_effect = [
        _resp(200, {"data": {"order": {"__typename": "Order", "email": "victim@example.com"}}}),
        _resp(200, {"data": {"order": None}, "errors": [{"message": "unauthorized"}]}),
    ]
    res = check_field_authz(
        "https://api.example.com/graphql", candidate, "12345",
        headers_privileged="Authorization: Bearer real-token", headers_unauth=None, timeout=5.0,
    )
    assert res.vulnerable is False
    assert res.status == "not_vulnerable"


@patch("tradecraft.adapters.graphql_authz_probe.execute.requests.post")
def test_check_field_authz_baseline_failed(mock_post):
    candidate = CandidateField(field_name="order", id_arg_name="orderId", id_arg_type="ID", scalar_fields=["email"])
    mock_post.return_value = _resp(200, {"data": {"order": None}})
    res = check_field_authz(
        "https://api.example.com/graphql", candidate, "bad-id",
        headers_privileged="Authorization: Bearer real-token", headers_unauth=None, timeout=5.0,
    )
    assert res.status == "baseline_failed"
    assert mock_post.call_count == 1  # never spends the unauth call if baseline already failed


def test_check_field_authz_degenerate_same_headers():
    candidate = CandidateField(field_name="order", id_arg_name="orderId", id_arg_type="ID", scalar_fields=["email"])
    with patch(
        "tradecraft.adapters.graphql_authz_probe.execute.requests.post",
        return_value=_resp(200, {"data": {"order": {"email": "x"}}}),
    ) as mock_post:
        res = check_field_authz(
            "https://api.example.com/graphql", candidate, "12345",
            headers_privileged=None, headers_unauth=None, timeout=5.0,
        )
    assert res.status == "degenerate_same_headers"
    assert mock_post.call_count == 1


# ---------------------------------------------------------------- execute()


@patch("tradecraft.adapters.graphql_authz_probe.execute.check_field_authz")
@patch("tradecraft.adapters.graphql_authz_probe.execute._extract_schema")
def test_execute_with_schema_json(mock_extract, mock_check):
    mock_extract.return_value = SCHEMA
    mock_check.return_value = MagicMock(vulnerable=True, field_name="order", status="vulnerable")
    out = execute("https://api.example.com/graphql", sample_id="123", schema_json=json.dumps(SCHEMA))
    assert out.vulnerable is True
    mock_extract.assert_called_once()


def test_execute_requires_sample_id():
    out = execute("https://api.example.com/graphql", sample_id="")
    assert out.error is not None


@patch("tradecraft.adapters.graphql_authz_probe.execute.fetch_schema")
def test_execute_schema_fetch_fails(mock_fetch):
    mock_fetch.return_value = None
    out = execute("https://api.example.com/graphql", sample_id="123")
    assert out.error is not None


# ---------------------------------------------------------------- parse()


def test_parse_includes_findings():
    from tradecraft.adapters.graphql_authz_probe.execute import FieldAuthzResult
    res = GraphqlAuthzResult(
        target="https://api.example.com/graphql",
        fields_checked=[FieldAuthzResult(field_name="order", vulnerable=True, status="vulnerable")],
        vulnerable=True,
        summary="order: VULNERABLE",
    )
    out = parse(res)
    assert len(out["findings"]) == 1
    assert "order" in out["findings"][0]
