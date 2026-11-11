"""
Parsing logic for linpeas: real linpeas.sh stdout, over SSH.

Pure functions, no I/O, no subprocess calls.

The marker logic below reflects real linpeas.sh output (the exact release
this adapter pulls from github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh),
not assumed section names:

- Real linpeas never prints "Clean SUID/SGID" or "CVEs Check" as section
  titles -- neither exists. The actual SUID/SGID section is titled
  "SUID - Check easy privesc, exploits and write perms" / "SGID", and a
  genuinely exploitable binary is flagged with a literal "--->" marker,
  only ever emitted when a SUID/SGID binary matches a known exploit-db
  entry (linpeas_builder's suid/sgid check).
- CVE checks are scattered across dozens of unrelated sections, mostly as
  a "Vulnerable to CVE-XXXX .... Yes/No" label that ALWAYS contains the
  word "Vulnerable" regardless of the actual answer -- so a genuine
  finding needs a negation check on the printed Yes/No value, not just a
  substring match on "Vulnerable".
- The BSD ``pkg audit`` section is titled "Vulnerable Packages", which
  also contains "Vulnerable" but is a section title, not a finding, and
  is excluded explicitly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

MAX_FINDINGS_RETURNED = 200
MAX_EVIDENCE_CHARS = 2_000_000

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_CVE_LABEL_VALUE_RE = re.compile(r"\.{2,}\s*(Yes|No)\s*$")

# A failed ssh/sshpass connection or authentication attempt never produces
# linpeas output -- without this check, an unreachable or wrong-credential
# host would be misreported as a clean 0-finding scan instead of a failed
# run, which this tool's own contract promises not to do.
_SSH_ERROR_INDICATORS = (
    "permission denied",
    "connection refused",
    "could not resolve hostname",
    "no route to host",
    "connection timed out",
    "host key verification failed",
)


@dataclass
class RawLinpeasResult:
    target: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def strip_ansi(text: str) -> str:
    """Removes ANSI color escape sequences from terminal output."""
    return _ANSI_RE.sub("", text or "")


def normalize_target_host(target: str) -> str:
    """Extracts the raw SSH host from a ``host`` or ``host:port`` target."""
    cleaned = (target or "").strip()
    if not cleaned:
        return ""
    if ":" in cleaned:
        parts = cleaned.split(":")
        if len(parts) == 2:
            return parts[0].strip()
    return cleaned


def parse_host_port(target: str) -> Tuple[str, Optional[int]]:
    """Splits a ``host`` or ``host:port`` SSH target.

    A port is only returned when the target carries an explicit
    ``:<digits>`` suffix -- there is no separate port parameter.
    """
    cleaned = (target or "").strip()
    if not cleaned:
        return "", None
    if ":" in cleaned:
        parts = cleaned.split(":")
        if len(parts) == 2 and parts[1].strip().isdigit():
            return parts[0].strip(), int(parts[1].strip())
    return cleaned, None


def detect_ssh_error(stdout: str, stderr: str) -> Optional[str]:
    """Detects an ssh/sshpass connection or authentication failure."""
    combined = f"{stdout or ''}\n{stderr or ''}"
    lowered = combined.lower()
    for indicator in _SSH_ERROR_INDICATORS:
        if indicator in lowered:
            for line in combined.splitlines():
                if indicator in line.lower():
                    return line.strip()
            return f"ssh error detected: {indicator}"
    return None


def parse_linpeas_findings(output: str) -> List[str]:
    """Parses real linpeas.sh stdout for high-probability SUID/SGID and
    CVE vectors, using the exact marker logic documented above."""
    findings: List[str] = []

    for line in (output or "").splitlines():
        # A SUID/SGID binary matched against the exploit-db lookup --
        # the only thing that ever prints "--->".
        if "--->" in line:
            findings.append(f"Potential SUID/SGID vector: {line.strip()}")
            continue

        if "Vulnerable" not in line:
            continue
        clean_line = strip_ansi(line).strip()
        # BSD `pkg audit` section title, not a finding.
        if clean_line == "Vulnerable Packages":
            continue
        # Some checks always print a "Vulnerable to CVE-XXXX .... Yes/No"
        # label regardless of the actual result -- only count it if the
        # printed value isn't "No".
        m = _CVE_LABEL_VALUE_RE.search(clean_line)
        if m and m.group(1) == "No":
            continue
        findings.append(f"Potential CVE vector: {clean_line}")

    return findings


def parse_linpeas_result(raw: RawLinpeasResult) -> Dict[str, Any]:
    """Turns a raw linpeas-over-SSH invocation into the model-facing
    result."""
    base: Dict[str, Any] = {"target": raw.target}

    if raw.error:
        return {**base, "status": "failed", "error": raw.error}

    ssh_error = detect_ssh_error(raw.stdout, raw.stderr)
    findings = parse_linpeas_findings(raw.stdout)

    if ssh_error and not findings and not strip_ansi(raw.stdout or "").strip():
        return {**base, "status": "failed", "error": ssh_error}

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
