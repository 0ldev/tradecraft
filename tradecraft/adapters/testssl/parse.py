"""
Pure parsing: testssl.sh's --csvfile output -> a list of flagged
findings (weak ciphers/protocols, named vulnerabilities like Heartbleed/
POODLE/ROBOT) with their severity. Filtering rules: skip neutral
protocol/service rows, keep only protocol/cipher/named-vuln rows with a
real severity. No subprocess, no I/O.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Dict, List, Optional, Tuple

_PROTOCOL_IDS = re.compile(
    r"^(ssl[23]|tls1(?:_\d)?|early_ccs|ccs|heartbleed|poodle|beast|robot|logjam|drown|freak)$",
    re.IGNORECASE,
)
_CIPHER_IDS = re.compile(r"^cipher_", re.IGNORECASE)
_NEUTRAL_PROTOCOLS = ("quic", "alpn", "alpn_http2", "http_status_code", "service")
_NAMED_VULNS = (
    "early_ccs", "ccs", "heartbleed", "poodle", "beast", "robot", "logjam",
    "drown", "freak", "ticketbleed",
)
_SEVERITY_ORDER = ("OK", "LOW", "WARN", "MEDIUM", "HIGH", "CRITICAL")


def parse_findings(csv_output: str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen = set()
    for row in csv.reader(io.StringIO(csv_output)):
        cleaned = [c.strip().strip('"') for c in row]
        if not cleaned or not cleaned[0] or len(cleaned) < 5:
            continue
        finding_id = cleaned[0].lower()
        if finding_id in ("id", *_NEUTRAL_PROTOCOLS):
            continue
        severity = cleaned[3].upper()
        detail = cleaned[4]
        is_protocol = bool(_PROTOCOL_IDS.match(finding_id))
        is_cipher = bool(_CIPHER_IDS.match(finding_id))
        is_named_vuln = finding_id in _NAMED_VULNS
        if not (is_protocol or is_cipher or is_named_vuln):
            continue
        if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN"):
            continue
        key = (finding_id, severity, detail)
        if key in seen:
            continue
        seen.add(key)
        findings.append({"id": finding_id, "severity": severity, "detail": detail})
    return findings


def parse_all_rows(csv_output: str) -> List[Dict[str, str]]:
    """Every row testssl emitted (including OK/INFO-severity and
    non-protocol/cipher/named-vuln ids that parse_findings filters out),
    for the evidence store. Without this, read_evidence on a testssl
    result with an empty findings list returns the exact same empty
    list it was already handed -- hydrating evidence on a sparse
    summary is a no-op unless the raw, unfiltered rows are kept
    somewhere. No subprocess, no I/O."""
    rows: List[Dict[str, str]] = []
    for row in csv.reader(io.StringIO(csv_output)):
        cleaned = [c.strip().strip('"') for c in row]
        if not cleaned or not cleaned[0] or len(cleaned) < 5:
            continue
        finding_id = cleaned[0].lower()
        if finding_id == "id":
            continue
        rows.append({"id": finding_id, "severity": cleaned[3].upper(), "detail": cleaned[4]})
    return rows


def worst_severity(findings: List[Dict[str, str]]) -> Optional[str]:
    if not findings:
        return None
    ranked = [f["severity"] for f in findings if f["severity"] in _SEVERITY_ORDER]
    if not ranked:
        return None
    return max(ranked, key=_SEVERITY_ORDER.index)


def host_port_from_target(target: str) -> Tuple[str, int]:
    """'host' -> (host, 443) (testssl's own default); 'host:port' -> (host, port)."""
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        if port_str.isdigit():
            return host, int(port_str)
    return target, 443
