"""
Parsing logic for winpeas: real winPEASany.exe stdout, run remotely via
Impacket's wmiexec.py.

Pure functions, no I/O, no subprocess calls.

Real winPEAS output markers, from PEASS-ng releases: modern releases use
'[!]' (square brackets) for critical findings; legacy releases may use
'(!)' or '(!CHECK!)' prefixes. ANSI color codes wrap the markers and are
stripped before parsing. A keyword fallback (Unquoted Service Path,
Modifiable Service, Weak Registry Permissions, DLL Hijacking, Scheduled
Task, Startup Folder, SeImpersonate, SeAssignPrimaryToken) covers
releases or inline text that omit an explicit marker.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

MAX_FINDINGS_RETURNED = 200
MAX_EVIDENCE_CHARS = 2_000_000

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_KEYWORD_FALLBACKS = (
    "Unquoted Service Path",
    "Modifiable Service",
    "Weak Registry Permissions",
    "DLL Hijacking",
    "Scheduled Task",
    "Startup Folder",
    "SeImpersonate",
    "SeAssignPrimaryToken",
)

# wmiexec.py never produces winPEAS output at all on an authentication
# or connection failure -- without this check, a failed run would be
# misreported as a clean 0-finding scan instead of a failed one.
_AUTH_FAILURE_MARKERS = ("STATUS_LOGON_FAILURE", "STATUS_ACCESS_DENIED")


@dataclass
class RawWinpeasResult:
    target: str = ""
    domain: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def strip_ansi(text: str) -> str:
    """Removes ANSI color escape sequences from terminal output."""
    return _ANSI_RE.sub("", text or "")


def normalize_target_host(target: str) -> str:
    """Extracts the raw host from a target string, dropping any explicit
    port suffix (wmiexec.py's own target is a bare host)."""
    cleaned = (target or "").strip()
    if not cleaned:
        return ""
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        cleaned = (parsed.hostname or cleaned).strip()
    if ":" in cleaned:
        cleaned = cleaned.split(":")[0].strip()
    return cleaned


def detect_auth_failure(stdout: str, stderr: str) -> Optional[str]:
    """Detects an authentication failure or unhandled exception in
    wmiexec.py's own output."""
    combined = f"{stdout or ''}\n{stderr or ''}"
    for marker in _AUTH_FAILURE_MARKERS:
        if marker in combined:
            return f"authentication failed: {marker}"
    if "Traceback" in combined and "Exception" in combined:
        lines = [line.strip() for line in combined.splitlines() if line.strip()]
        tail = lines[-1] if lines else "unhandled exception in wmiexec.py"
        return f"wmiexec.py raised an exception: {tail}"
    return None


def parse_winpeas_findings(output: str) -> List[str]:
    """Parses real winPEASany.exe stdout for high-confidence findings
    using both explicit marker matching and keyword detection."""
    findings: List[str] = []

    for line in (output or "").splitlines():
        line_clean = strip_ansi(line).strip()
        if not line_clean:
            continue

        if "[!]" in line_clean or "(!)" in line_clean or "(!CHECK!)" in line_clean:
            findings.append(f"Potential privilege escalation vector: {line_clean}")
            continue

        if any(keyword in line_clean for keyword in _KEYWORD_FALLBACKS):
            findings.append(f"Potential privilege escalation vector: {line_clean}")

    return findings


def parse_winpeas_result(raw: RawWinpeasResult) -> Dict[str, Any]:
    """Turns a raw winPEAS-over-wmiexec.py invocation into the
    model-facing result."""
    base: Dict[str, Any] = {"target": raw.target, "domain": raw.domain}

    if raw.error:
        return {**base, "status": "failed", "error": raw.error}

    auth_error = detect_auth_failure(raw.stdout, raw.stderr)
    if auth_error:
        return {**base, "status": "failed", "error": auth_error}

    findings = parse_winpeas_findings(raw.stdout)
    return {
        **base,
        "status": "success",
        "finding_count": len(findings),
        "findings": findings[:MAX_FINDINGS_RETURNED],
        "findings_truncated": len(findings) > MAX_FINDINGS_RETURNED,
    }


def cap_evidence(text: str) -> str:
    """Bounds the transcript stored as evidence to MAX_EVIDENCE_CHARS."""
    text = text or ""
    if len(text) <= MAX_EVIDENCE_CHARS:
        return text
    return text[:MAX_EVIDENCE_CHARS]
