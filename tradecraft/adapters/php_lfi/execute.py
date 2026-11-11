"""
Network execution for php_lfi: tests a parameter with bounded traversal payloads.
No parsing logic here -- see parse.py.
"""
from __future__ import annotations

from typing import Optional

import requests
import urllib3

from tradecraft.adapters.php_lfi import parse as lfi_parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_BODY_CHARS = 50000


def execute(
    target: str,
    parameter: str,
    file_path: str = "",
    timeout: int = 15,
    session: Optional[requests.Session] = None,
) -> lfi_parse.RawLfiResult:
    """Executes HTTP requests with standard LFI payloads against target and parameter."""
    target_url = lfi_parse.normalize_target_url(target)
    if not target_url:
        return lfi_parse.RawLfiResult(error="empty target URL")
    if not parameter:
        return lfi_parse.RawLfiResult(target=target_url, error="missing required parameter")

    payloads = lfi_parse.build_lfi_payloads(target_file=file_path)
    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True

    result = lfi_parse.RawLfiResult(target=target_url, parameter=parameter)

    try:
        for payload, desc in payloads:
            probe_url = lfi_parse.build_probe_url(target_url, parameter, payload)
            try:
                resp = session.get(
                    probe_url,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) tradecraft/1.0"},
                )
                body = resp.text[:MAX_BODY_CHARS]
                probe = lfi_parse.RawLfiProbe(
                    payload=payload,
                    file_description=desc,
                    status_code=resp.status_code,
                    url=resp.url,
                    body=body,
                )
                result.probes.append(probe)
                result.tested_count += 1

                is_lfi, _, _ = lfi_parse.check_lfi_response(body)
                if is_lfi:
                    break
            except requests.RequestException as e:
                result.probes.append(
                    lfi_parse.RawLfiProbe(
                        payload=payload,
                        file_description=desc,
                        url=probe_url,
                        error=str(e),
                    )
                )
                result.tested_count += 1
    finally:
        if close_session:
            session.close()

    return result
