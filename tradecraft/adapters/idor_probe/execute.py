"""
Execution logic for IDOR (Insecure Direct Object Reference) and differential
object probing. Performs bounded, read-only GET requests across baseline and
candidate object IDs.
"""
from __future__ import annotations

import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

DEFAULT_TIMEOUT = 10
MAX_CANDIDATES = 3
ID_PARAM_NAMES = (
    "id", "user_id", "userid", "uid", "account_id", "order_id", "order",
    "doc_id", "doc", "invoice_id", "invoice", "file_id", "file", "item_id",
    "item", "customer_id", "num", "no", "code", "p", "report_id", "profile_id",
)


@dataclass
class TargetPlan:
    url_template: str
    param_name: str
    is_path: bool
    baseline_value: str
    candidate_values: List[str]
    error: Optional[str] = None


@dataclass
class RawHttpResponse:
    url: str
    tested_id: str
    status_code: int = 0
    content_type: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_length: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None


@dataclass
class RawIdorResult:
    target: str = ""
    param: str = ""
    baseline_id: str = ""
    baseline_response: Optional[RawHttpResponse] = None
    probes: List[RawHttpResponse] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        return ""
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


def resolve_target_plan(
    target: str,
    param: Optional[str] = None,
    candidate_values: Optional[str] = None,
) -> TargetPlan:
    url = normalize_target_url(target)
    if not url:
        return TargetPlan(
            url_template="",
            param_name="",
            is_path=False,
            baseline_value="",
            candidate_values=[],
            error="empty target URL provided",
        )

    parsed = urllib.parse.urlsplit(url)
    query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_dict = dict(query_params)
    path_segments = [s for s in parsed.path.split("/") if s]

    url_template = ""
    param_name = ""
    is_path = False
    baseline_value = ""

    # 1. Explicit placeholder in target URL: {ID} or {id}
    if "{ID}" in url or "{id}" in url:
        placeholder = "{ID}" if "{ID}" in url else "{id}"
        url_template = url.replace(placeholder, "{ID}")
        param_name = param or "path_segment"
        is_path = True
        baseline_value = "1"
    # 2. User specified param name explicitly
    elif param:
        param_clean = param.strip()
        if param_clean in query_dict:
            param_name = param_clean
            baseline_value = query_dict[param_clean]
            is_path = False
            new_query_params = []
            for k, v in query_params:
                if k == param_clean:
                    new_query_params.append((k, "{ID}"))
                else:
                    new_query_params.append((k, v))
            new_qs = urllib.parse.urlencode(new_query_params, safe="{}")
            url_template = urllib.parse.urlunsplit(parsed._replace(query=new_qs))
        else:
            matched_idx = -1
            for idx, seg in enumerate(path_segments):
                if seg.lower() == param_clean.lower():
                    matched_idx = idx
                    break
            if matched_idx >= 0:
                param_name = param_clean
                baseline_value = path_segments[matched_idx]
                is_path = True
                new_segments = list(path_segments)
                new_segments[matched_idx] = "{ID}"
                new_path = "/" + "/".join(new_segments)
                if parsed.path.endswith("/"):
                    new_path += "/"
                url_template = urllib.parse.urlunsplit(parsed._replace(path=new_path))
            else:
                return TargetPlan(
                    url_template="",
                    param_name=param_clean,
                    is_path=False,
                    baseline_value="",
                    candidate_values=[],
                    error=f"specified parameter '{param_clean}' not found in query string or URL path",
                )
    # 3. Auto-detect ID parameter or path segment
    else:
        picked_param: Optional[Tuple[str, str]] = None
        if query_params:
            # Prioritize standard ID parameter names
            for k, v in query_params:
                if k.lower() in ID_PARAM_NAMES and v.strip():
                    picked_param = (k, v)
                    break
            # Fallback to any parameter with an integer value
            if not picked_param:
                for k, v in query_params:
                    if re.fullmatch(r"\d+", v.strip()):
                        picked_param = (k, v)
                        break
            # Fallback to the first query parameter with a value
            if not picked_param:
                for k, v in query_params:
                    if v.strip():
                        picked_param = (k, v)
                        break

        if picked_param:
            param_name = picked_param[0]
            baseline_value = picked_param[1]
            is_path = False
            new_query_params = []
            for k, v in query_params:
                if k == param_name:
                    new_query_params.append((k, "{ID}"))
                else:
                    new_query_params.append((k, v))
            new_qs = urllib.parse.urlencode(new_query_params, safe="{}")
            url_template = urllib.parse.urlunsplit(parsed._replace(query=new_qs))
        else:
            numeric_idx = -1
            for idx in range(len(path_segments) - 1, -1, -1):
                if re.fullmatch(r"\d+", path_segments[idx]):
                    numeric_idx = idx
                    break

            if numeric_idx >= 0:
                param_name = "path_segment"
                baseline_value = path_segments[numeric_idx]
                is_path = True
                new_segments = list(path_segments)
                new_segments[numeric_idx] = "{ID}"
                new_path = "/" + "/".join(new_segments)
                if parsed.path.endswith("/"):
                    new_path += "/"
                url_template = urllib.parse.urlunsplit(parsed._replace(path=new_path))
            else:
                return TargetPlan(
                    url_template="",
                    param_name="",
                    is_path=False,
                    baseline_value="",
                    candidate_values=[],
                    error=(
                        "No object identifier found in target URL; specify 'param' or supply "
                        "a URL with query parameters or a numeric path segment (e.g. '?id=105' or '/orders/105')."
                    ),
                )

    candidates_list: List[str] = []
    if candidate_values:
        raw_cands = [c.strip() for c in candidate_values.split(",") if c.strip()]
        seen = {baseline_value}
        for c in raw_cands:
            if c not in seen:
                seen.add(c)
                candidates_list.append(c)
        if not candidates_list:
            return TargetPlan(
                url_template=url_template,
                param_name=param_name,
                is_path=is_path,
                baseline_value=baseline_value,
                candidate_values=[],
                error="No valid candidate values provided (cannot be empty or identical to baseline).",
            )
        candidates_list = candidates_list[:MAX_CANDIDATES]
    else:
        # Auto-step if baseline is integer
        if re.fullmatch(r"-?\d+", baseline_value):
            base_int = int(baseline_value)
            cands = [str(base_int + 1)]
            if base_int > 1:
                cands.append(str(base_int - 1))
            elif base_int == 1:
                cands.append("2")
            if "1" not in cands and baseline_value != "1":
                cands.append("1")
            elif "0" not in cands and baseline_value != "0":
                cands.append("0")

            seen = {baseline_value}
            for c in cands:
                if c not in seen:
                    seen.add(c)
                    candidates_list.append(c)
            candidates_list = candidates_list[:MAX_CANDIDATES]
        else:
            return TargetPlan(
                url_template=url_template,
                param_name=param_name,
                is_path=is_path,
                baseline_value=baseline_value,
                candidate_values=[],
                error=(
                    f"Baseline value '{baseline_value}' is non-numeric; automatic stepping requires an integer. "
                    "Provide candidate_values explicitly (e.g. candidate_values='id2,id3')."
                ),
            )

    return TargetPlan(
        url_template=url_template,
        param_name=param_name,
        is_path=is_path,
        baseline_value=baseline_value,
        candidate_values=candidates_list,
    )


def build_url_for_value(template: str, value: str) -> str:
    quoted = urllib.parse.quote(str(value), safe="")
    if "{ID}" in template:
        return template.replace("{ID}", quoted)
    if "%7BID%7D" in template:
        return template.replace("%7BID%7D", quoted)
    if "%7Bid%7D" in template:
        return template.replace("%7Bid%7D", quoted)
    return template


def parse_custom_headers(headers_str: Optional[str]) -> Dict[str, str]:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0",
        "Accept": "*/*",
    }
    if headers_str:
        for line in headers_str.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    return headers


def execute(
    target: str,
    param: Optional[str] = None,
    candidate_values: Optional[str] = None,
    headers: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawIdorResult:
    if requests is None:
        return RawIdorResult(target=target, error="requests library not available in runtime environment")

    plan = resolve_target_plan(target=target, param=param, candidate_values=candidate_values)
    if plan.error:
        return RawIdorResult(target=target, error=plan.error)

    req_headers = parse_custom_headers(headers)
    baseline_url = build_url_for_value(plan.url_template, plan.baseline_value)

    # 1. Baseline Request
    t0 = time.time()
    try:
        resp = requests.get(
            baseline_url,
            headers=req_headers,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        duration = round(time.time() - t0, 3)
        baseline_res = RawHttpResponse(
            url=resp.url,
            tested_id=plan.baseline_value,
            status_code=resp.status_code,
            content_type=resp.headers.get("content-type", ""),
            headers=dict(resp.headers),
            body=resp.text or "",
            body_length=len(resp.text or ""),
            duration_seconds=duration,
        )
    except requests.RequestException as exc:
        return RawIdorResult(
            target=target,
            param=plan.param_name,
            baseline_id=plan.baseline_value,
            error=f"Baseline request to '{baseline_url}' failed: {exc}",
        )
    except Exception as exc:
        return RawIdorResult(
            target=target,
            param=plan.param_name,
            baseline_id=plan.baseline_value,
            error=f"Baseline request error: {type(exc).__name__}: {exc}",
        )

    # 2. Candidate Probes (strictly GET, hard-capped at MAX_CANDIDATES)
    probes: List[RawHttpResponse] = []
    for cand in plan.candidate_values[:MAX_CANDIDATES]:
        probe_url = build_url_for_value(plan.url_template, cand)
        t_cand = time.time()
        try:
            cand_resp = requests.get(
                probe_url,
                headers=req_headers,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            cand_duration = round(time.time() - t_cand, 3)
            probes.append(
                RawHttpResponse(
                    url=cand_resp.url,
                    tested_id=cand,
                    status_code=cand_resp.status_code,
                    content_type=cand_resp.headers.get("content-type", ""),
                    headers=dict(cand_resp.headers),
                    body=cand_resp.text or "",
                    body_length=len(cand_resp.text or ""),
                    duration_seconds=cand_duration,
                )
            )
        except requests.RequestException as exc:
            probes.append(
                RawHttpResponse(
                    url=probe_url,
                    tested_id=cand,
                    error=str(exc),
                )
            )
        except Exception as exc:
            probes.append(
                RawHttpResponse(
                    url=probe_url,
                    tested_id=cand,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    return RawIdorResult(
        target=target,
        param=plan.param_name,
        baseline_id=plan.baseline_value,
        baseline_response=baseline_res,
        probes=probes,
    )
