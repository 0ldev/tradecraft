"""
Execution logic for graphql_authz_probe: picks ID-shaped Query-type
fields from a GraphQL schema and tests whether an unauthenticated
request still resolves the same object a privileged request resolves --
Broken Object Level Authorization (BOLA) via a GraphQL query. Deliberately
scoped to queries only, never mutations, to stay safely non-destructive.
No parsing of the per-field result shape happens here beyond extracting
`data.<field>` -- the full result list formatting is parse.py's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
MAX_CANDIDATE_FIELDS = 5

ID_ARG_MARKERS = ("id", "key", "uuid")
LOOKUP_FIELD_NAMES = ("user", "order", "account", "invoice", "customer", "profile", "record")
SCALAR_FIELD_CANDIDATES = ("id", "name", "email", "username")

# A deeper introspection than graphql_introspect's own (which only
# fetches type names/kinds) -- this one needs each Query field's args
# and its return type's own fields to build a minimal real query.
SCHEMA_QUERY = {
    "query": """
    query {
      __schema {
        queryType {
          name
          fields {
            name
            args { name type { name kind ofType { name kind } } }
            type {
              name
              kind
              fields { name type { name kind ofType { name kind } } }
            }
          }
        }
      }
    }
    """
}


@dataclass
class CandidateField:
    field_name: str
    id_arg_name: str
    id_arg_type: str = "String"
    scalar_fields: List[str] = field(default_factory=list)


@dataclass
class FieldAuthzResult:
    field_name: str
    query: str = ""
    baseline_status: Optional[int] = None
    baseline_resolved: bool = False
    unauth_status: Optional[int] = None
    unauth_resolved: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "not_vulnerable", "baseline_failed", "degenerate_same_headers"
    error: Optional[str] = None


@dataclass
class GraphqlAuthzResult:
    target: str = ""
    fields_checked: List[FieldAuthzResult] = field(default_factory=list)
    vulnerable: bool = False
    summary: str = ""
    error: Optional[str] = None


def _unwrap_type_name(type_obj: Dict) -> str:
    name = type_obj.get("name")
    if name:
        return name
    of_type = type_obj.get("ofType") or {}
    return of_type.get("name") or ""


def fetch_schema(url: str, timeout: float) -> Optional[Dict]:
    if requests is None:
        return None
    try:
        resp = requests.post(
            url, json=SCHEMA_QUERY,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
            timeout=timeout, verify=False,
        )
    except requests.RequestException:
        return None
    try:
        body = resp.json()
    except ValueError:
        return None
    schema = (body.get("data") or {}).get("__schema")
    return schema if isinstance(schema, dict) else None


def _build_candidate(f: Dict, id_arg: Dict) -> CandidateField:
    arg_type_name = _unwrap_type_name(id_arg.get("type") or {})
    return_type = f.get("type") or {}
    return_fields = return_type.get("fields") or []
    scalar_fields = [
        rf.get("name") for rf in return_fields
        if isinstance(rf, dict) and rf.get("name") in SCALAR_FIELD_CANDIDATES
    ]
    return CandidateField(
        field_name=f.get("name", ""),
        id_arg_name=id_arg.get("name", ""),
        id_arg_type=arg_type_name or "String",
        scalar_fields=scalar_fields,
    )


def select_candidate_fields(schema: Dict, max_fields: int = MAX_CANDIDATE_FIELDS) -> List[CandidateField]:
    """An id-shaped arg is required regardless of field name -- there is
    no argument to inject sample_id into otherwise. Among fields that
    qualify, a lookup-shaped field name (user/order/account/...) is
    prioritized first, since it is the stronger BOLA signal; any other
    id-shaped field fills the remaining slots up to max_fields."""
    query_type = schema.get("queryType") or {}
    fields = query_type.get("fields") or []

    lookup_named: List[CandidateField] = []
    other: List[CandidateField] = []

    for f in fields:
        if not isinstance(f, dict):
            continue
        field_name = f.get("name", "")
        args = f.get("args") or []

        id_arg = None
        for a in args:
            arg_name = a.get("name") or ""
            if any(marker in arg_name.lower() for marker in ID_ARG_MARKERS):
                id_arg = a
                break
        if id_arg is None:
            continue

        candidate = _build_candidate(f, id_arg)
        if any(kw in field_name.lower() for kw in LOOKUP_FIELD_NAMES):
            lookup_named.append(candidate)
        else:
            other.append(candidate)

    return (lookup_named + other)[:max_fields]


def build_query(candidate: CandidateField, sample_id: str) -> str:
    value = sample_id if candidate.id_arg_type in ("Int", "Float") else f'"{sample_id}"'
    selection = " ".join(["__typename"] + candidate.scalar_fields) if candidate.scalar_fields else "__typename"
    return f"query {{ {candidate.field_name}({candidate.id_arg_name}: {value}) {{ {selection} }} }}"


def parse_headers(headers_str: Optional[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if headers_str:
        for line in headers_str.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    return headers


def _run_query(url: str, query: str, extra_headers: Dict[str, str], timeout: float) -> Tuple[Optional[int], Optional[Dict]]:
    if requests is None:
        return None, None
    req_headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    req_headers.update(extra_headers)
    try:
        resp = requests.post(url, json={"query": query}, headers=req_headers, timeout=timeout, verify=False)
    except requests.RequestException:
        return None, None
    try:
        body = resp.json()
    except ValueError:
        body = None
    return resp.status_code, body


def check_field_authz(
    url: str, candidate: CandidateField, sample_id: str,
    headers_privileged: Optional[str], headers_unauth: Optional[str], timeout: float,
) -> FieldAuthzResult:
    res = FieldAuthzResult(field_name=candidate.field_name)
    query = build_query(candidate, sample_id)
    res.query = query

    priv_headers = parse_headers(headers_privileged)
    unauth_headers = parse_headers(headers_unauth)

    baseline_status, baseline_body = _run_query(url, query, priv_headers, timeout)
    res.baseline_status = baseline_status
    baseline_data = ((baseline_body or {}).get("data") or {}).get(candidate.field_name)
    res.baseline_resolved = baseline_data is not None
    if not res.baseline_resolved:
        res.status = "baseline_failed"
        return res

    if priv_headers == unauth_headers:
        # No actual privilege differential between the two calls -- can't
        # prove unauthenticated exposure from an identical request.
        res.status = "degenerate_same_headers"
        return res

    unauth_status, unauth_body = _run_query(url, query, unauth_headers, timeout)
    res.unauth_status = unauth_status
    unauth_data = ((unauth_body or {}).get("data") or {}).get(candidate.field_name)
    res.unauth_resolved = unauth_data is not None
    if res.unauth_resolved:
        res.vulnerable = True
        res.status = "vulnerable"
    else:
        res.status = "not_vulnerable"
    return res


def _extract_schema(schema_json: str) -> Optional[Dict]:
    try:
        doc = json.loads(schema_json)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    if "queryType" in doc:
        return doc
    schema = (doc.get("data") or {}).get("__schema")
    return schema if isinstance(schema, dict) else None


def execute(
    target: str,
    sample_id: str,
    schema_json: Optional[str] = None,
    headers_privileged: Optional[str] = None,
    headers_unauth: Optional[str] = None,
    timeout: int = 10,
) -> GraphqlAuthzResult:
    url = (target or "").strip()
    if not url:
        return GraphqlAuthzResult(target=target, error="empty target")
    if not sample_id:
        return GraphqlAuthzResult(target=target, error="sample_id is required")

    effective_timeout = max(1.0, min(float(timeout), 20.0))

    schema = _extract_schema(schema_json) if schema_json else fetch_schema(url, effective_timeout)
    if not schema:
        return GraphqlAuthzResult(
            target=target,
            error="could not obtain a usable GraphQL schema (introspection failed and no schema_json given)",
        )

    candidates = select_candidate_fields(schema)
    if not candidates:
        return GraphqlAuthzResult(target=target, error="no ID-shaped query fields found in schema to test")

    results = [
        check_field_authz(url, c, sample_id, headers_privileged, headers_unauth, effective_timeout)
        for c in candidates
    ]
    is_vuln = any(r.vulnerable for r in results)
    summary_parts = [f"{r.field_name}: {'VULNERABLE' if r.vulnerable else r.status}" for r in results]

    return GraphqlAuthzResult(target=target, fields_checked=results, vulnerable=is_vuln, summary="; ".join(summary_parts))
