"""
Parsing logic for kube_hunter_enum: passive kube-hunter JSON reports.

Pure functions, no I/O, no subprocess calls.

kube-hunter's JSON reporter (``kube_hunter.modules.report.base.BaseReporter``)
emits exactly:

    {
      "nodes": [{"type": "Node/Master", "location": "<host>"}],
      "services": [{"service": "<name>", "location": "<host>:<port><path>"}],
      "vulnerabilities": [{
          "location": "<host>:<port>",
          "vid": "KHV...",
          "category": "Initial Access // Exposed sensitive interfaces",
          "severity": "high",
          "vulnerability": "...",
          "description": "...",
          "evidence": "...",
          "avd_reference": "https://avd.aquasec.com/kube-hunter/khv.../",
          "hunter": "API Server Hunter"
      }]
    }

Entries are passed through as kube-hunter emitted them rather than
re-normalised into a second schema that would drift from the tool.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

MAX_NODES_RETURNED = 50
MAX_SERVICES_RETURNED = 100
MAX_VULNERABILITIES_RETURNED = 200
MAX_EVIDENCE_CHARS = 2_000_000

SEVERITIES = ("critical", "high", "medium", "low")

# An IPv4 range such as 10.0.0.1-10.0.0.50. kube-hunter's --remote takes a
# host, not a range; --cidr takes a single CIDR.
_IPV4_RANGE_REGEX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}\s*-\s*\d")


@dataclass
class RawKubeHunterResult:
    target: str = ""
    target_kind: str = ""  # "host" or "cidr"
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def normalize_target_host(target: str) -> str:
    """Extracts the raw host from a target string.

    A URL's hostname is kept; an explicit ``host:port`` suffix is dropped.
    IPv6 brackets are unwrapped. CIDRs are not passed here -- see
    ``parse_target``.
    """
    cleaned = (target or "").strip()
    if not cleaned:
        return ""
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        return (parsed.hostname or "").strip()
    if cleaned.startswith("["):
        end = cleaned.find("]")
        if end != -1:
            return cleaned[1:end]
    if cleaned.count(":") == 1:
        host, _, maybe_port = cleaned.partition(":")
        if maybe_port.isdigit():
            return host.strip()
    return cleaned.strip("/[] ")


def parse_target(target: str) -> Tuple[str, str, Optional[str]]:
    """Normalises a target into ``(kind, value, error)``.

    ``kind`` is ``"host"`` or ``"cidr"``. Only one host or one IPv4 CIDR
    no broader than /24 is accepted: kube-hunter's ``--remote`` and
    ``--cidr`` both accept broader input than this tool should send.
    """
    raw = (target or "").strip()
    if not raw:
        return "", "", "empty target host"

    if "://" in raw:
        raw = (urlparse(raw).hostname or "").strip()
        if not raw:
            return "", "", "could not extract a host from target URL"

    if "," in raw:
        return "", "", (
            "kube_hunter_enum scans a single host or one CIDR /24 or "
            "narrower; target lists are not accepted"
        )
    if _IPV4_RANGE_REGEX.match(raw):
        return "", "", (
            "kube_hunter_enum scans a single host or one CIDR /24 or "
            "narrower; IP ranges are not accepted"
        )

    if "/" in raw:
        if raw.startswith("/") or os.path.exists(raw):
            return "", "", (
                "invalid target: looks like a local file, not a host or CIDR"
            )
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return "", "", f"invalid CIDR '{raw}'"
        if network.version != 4:
            return "", "", "only IPv4 CIDR ranges are supported"
        if network.prefixlen < 24:
            return "", "", (
                f"CIDR '{raw}' is broader than /24; kube_hunter_enum caps "
                "scans at /24"
            )
        return "cidr", str(network), None

    if os.path.exists(raw) or "\\" in raw:
        return "", "", "invalid target: looks like a local path, not a host"

    host = normalize_target_host(raw)
    if not host:
        return "", "", "empty target host"
    if any(char.isspace() for char in host) or "," in host:
        return "", "", "invalid target host"
    return "host", host, None


def parse_host_port(location: str) -> Tuple[str, Optional[int]]:
    """Splits kube-hunter's ``host:port[/path]`` locations.

    Returns ``(host, port)`` with ``port=None`` when the location carries
    no port (kube-hunter's node locations are bare hosts).
    """
    text = (location or "").strip()
    if not text:
        return "", None

    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return text, None
        host = text[1:end]
        rest = text[end + 1 :]
        if rest.startswith(":"):
            port_text = rest[1:].split("/", 1)[0]
            if port_text.isdigit():
                return host, int(port_text)
        return host, None

    before_path = text.split("/", 1)[0]
    if before_path.count(":") == 1:
        host, _, port_text = before_path.partition(":")
        if port_text.isdigit():
            return host, int(port_text)
        return host, None
    if before_path.count(":") > 1:
        # Bare IPv6 without brackets; no port suffix.
        return before_path, None
    return before_path, None


def _dict_list(value: Any) -> Optional[List[Dict[str, Any]]]:
    if not isinstance(value, list):
        return None
    return [entry for entry in value if isinstance(entry, dict)]


def _severity_counts(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    counts["unknown"] = 0
    for vulnerability in vulnerabilities:
        severity = str(vulnerability.get("severity", "")).strip().lower()
        if severity in SEVERITIES:
            counts[severity] += 1
        else:
            counts["unknown"] += 1
    return counts


def parse_kube_hunter_report(json_text: str) -> Dict[str, Any]:
    """Parses kube-hunter's JSON report into counts, capped entries, and
    severity totals. A malformed document is a real parse failure, not
    "found nothing"."""
    try:
        data = json.loads(json_text)
    except (TypeError, ValueError) as exc:
        return {
            "status": "failed",
            "error": f"could not parse kube-hunter JSON report: {exc}",
        }

    if not isinstance(data, dict):
        return {
            "status": "failed",
            "error": (
                "could not parse kube-hunter JSON report: top-level value "
                f"is {type(data).__name__}, expected an object"
            ),
        }

    nodes = _dict_list(data.get("nodes", []))
    services = _dict_list(data.get("services", []))
    vulnerabilities = _dict_list(data.get("vulnerabilities", []))
    if nodes is None or services is None or vulnerabilities is None:
        return {
            "status": "failed",
            "error": (
                "kube-hunter JSON report has an unexpected shape: "
                "nodes/services/vulnerabilities must be lists"
            ),
        }

    result: Dict[str, Any] = {
        "status": "success",
        "mode": "passive",
        "node_count": len(nodes),
        "service_count": len(services),
        "vulnerability_count": len(vulnerabilities),
        "severity_counts": _severity_counts(vulnerabilities),
        "nodes": nodes[:MAX_NODES_RETURNED],
        "services": services[:MAX_SERVICES_RETURNED],
        "vulnerabilities": vulnerabilities[:MAX_VULNERABILITIES_RETURNED],
        "nodes_truncated": len(nodes) > MAX_NODES_RETURNED,
        "services_truncated": len(services) > MAX_SERVICES_RETURNED,
        "vulnerabilities_truncated": (
            len(vulnerabilities) > MAX_VULNERABILITIES_RETURNED
        ),
    }

    if not nodes and not services:
        result["notes"] = [
            "kube-hunter found no Kubernetes nodes or services; the "
            "target may not be a cluster or may be unreachable."
        ]

    return result


def _find_report(stdout: str) -> Optional[Dict[str, Any]]:
    """Finds a parseable JSON report in stdout.

    kube-hunter is invoked with ``--log none`` so stdout is normally the
    report alone, but tolerate leading/trailing log lines by also trying
    the last non-empty line.
    """
    out = (stdout or "").strip()
    if not out:
        return None

    candidates = [out]
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if len(lines) > 1:
        candidates.append(lines[-1])

    for candidate in candidates:
        parsed = parse_kube_hunter_report(candidate)
        if parsed.get("status") == "success":
            return parsed
    return None


def _tail(text: str) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1] if lines else ""


def parse_kube_hunter_enum_result(
    raw: RawKubeHunterResult,
) -> Dict[str, Any]:
    """Turns a raw passive kube-hunter invocation into the model-facing
    result.

    kube-hunter exits 0 even when it finds nothing (and, notably, for an
    unresolvable target), so the exit code is not used to decide success.
    """
    base = {
        "target": raw.target,
        "target_kind": raw.target_kind,
        "mode": "passive",
    }

    if raw.error:
        return {**base, "status": "failed", "error": raw.error}

    parsed = _find_report(raw.stdout)
    if parsed is not None:
        return {**base, **parsed}

    combined = f"{raw.stdout or ''}\n{raw.stderr or ''}"
    if "couldn't find any clusters" in combined.lower():
        return {
            **base,
            "status": "no_response",
            "notes": ["kube-hunter could not find any clusters at the target."],
        }

    error = _tail(raw.stderr) or _tail(raw.stdout)
    if error:
        return {**base, "status": "failed", "error": error}

    return {
        **base,
        "status": "failed",
        "error": (
            "kube-hunter produced no JSON report "
            f"(exit code {raw.returncode})"
        ),
    }


def cap_evidence(text: str) -> str:
    """Bounds the transcript stored as evidence to MAX_EVIDENCE_CHARS."""
    if len(text) <= MAX_EVIDENCE_CHARS:
        return text
    return text[:MAX_EVIDENCE_CHARS]
