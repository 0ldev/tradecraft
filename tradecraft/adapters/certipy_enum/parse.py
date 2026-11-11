"""
Parsing logic for certipy_enum: Certipy's `find` JSON output.

Pure functions, no I/O, no subprocess calls.

Certipy writes the JSON to `<prefix>_Certipy.json`; ``execute.py`` reads
that file and hands the text here. The top-level shape is produced by
``certipy.commands.find.Find.get_output_for_text_and_json``:

    {
      "Certificate Authorities": {
        "0": { ...properties..., "Permissions": {...},
               "[!] Vulnerabilities": {...} },
        ...
      },
      "Certificate Templates": {
        "0": { ...properties..., "Permissions": {...},
               "[!] Vulnerabilities": {...} },
        ...
      }
    }

Either section is the string ``"[!] Could not find any ..."`` when
nothing was found. The per-entry property names are Certipy's own
(``Template Name``, ``CA Name``, ``Enabled``, etc.), so entries are passed
through rather than re-normalised into a second schema that would drift
from the tool.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

MAX_CAS_RETURNED = 25
MAX_TEMPLATES_RETURNED = 100
MAX_VULNERABLE_SUMMARIES = 50
MAX_EVIDENCE_CHARS = 2_000_000

# Certipy logs errors on stdout as "[-] ..." (it exits 0 even on failure).
_ERROR_LINE_REGEX = re.compile(r"^\[-\]\s*(?P<text>.+)$", re.MULTILINE)


@dataclass
class RawCertipyEnumResult:
    target: str = ""
    domain: str = ""
    scheme: str = "ldaps"
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    json_output: Optional[str] = None
    error: Optional[str] = None


def extract_error_lines(text: str) -> List[str]:
    """Returns the text of Certipy's ``[-] ...`` log lines, in order."""
    return [
        match.group("text").strip()
        for match in _ERROR_LINE_REGEX.finditer(text or "")
    ]


def normalize_target_host(target: str) -> str:
    """Extracts the raw host from a target string.

    A URL's hostname is kept; an explicit ``host:port`` suffix is dropped.
    IPv6 brackets are unwrapped. Certipy targets a DC, so the caller's
    validator still rejects CIDR/list/file forms.
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


def _entries_from_section(
    value: Any,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Normalises one Certipy JSON section into a list of entry dicts.

    Returns ``(entries, note)`` where ``note`` is the "could not find any"
    string when Certipy emitted one instead of a mapping.
    """
    if isinstance(value, str):
        return [], value

    if isinstance(value, dict):
        items = list(value.items())

        def sort_key(item: Tuple[str, Any]) -> Tuple[int, str]:
            key = str(item[0])
            return (int(key), "") if key.isdigit() else (2**31 - 1, key)

        entries = [
            entry
            for _, entry in sorted(items, key=sort_key)
            if isinstance(entry, dict)
        ]
        return entries, None

    if isinstance(value, list):
        return [entry for entry in value if isinstance(entry, dict)], None

    return [], None


def _vulnerability_names(entry: Dict[str, Any]) -> List[str]:
    vulnerabilities = entry.get("[!] Vulnerabilities")
    if isinstance(vulnerabilities, dict):
        return sorted(str(key) for key in vulnerabilities.keys())
    if isinstance(vulnerabilities, list):
        return sorted(str(item) for item in vulnerabilities)
    return []


def _entry_name(entry: Dict[str, Any], *keys: str, default: str) -> str:
    for key in keys:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default


def _summarise_vulnerable(
    entries: List[Dict[str, Any]], name_keys: Tuple[str, ...]
) -> List[Dict[str, Any]]:
    summaries = []
    for entry in entries:
        vulnerabilities = _vulnerability_names(entry)
        if not vulnerabilities:
            continue
        summaries.append(
            {
                "name": _entry_name(entry, *name_keys, default="(unnamed)"),
                "vulnerabilities": vulnerabilities,
            }
        )
    return summaries[:MAX_VULNERABLE_SUMMARIES]


def parse_certipy_json(json_text: str) -> Dict[str, Any]:
    """Parses Certipy's `find` JSON into counts, entries, and summaries.

    Returns a partial result with ``status`` set. A malformed document is
    a real parse failure, not "found nothing".
    """
    try:
        data = json.loads(json_text)
    except (TypeError, ValueError) as exc:
        return {
            "status": "failed",
            "error": f"could not parse certipy JSON output: {exc}",
        }

    if not isinstance(data, dict):
        return {
            "status": "failed",
            "error": (
                "could not parse certipy JSON output: top-level value is "
                f"{type(data).__name__}, expected an object"
            ),
        }

    cas, ca_note = _entries_from_section(data.get("Certificate Authorities"))
    templates, template_note = _entries_from_section(
        data.get("Certificate Templates")
    )

    notes: List[str] = []
    if ca_note:
        notes.append(f"Certificate Authorities: {ca_note}")
    if template_note:
        notes.append(f"Certificate Templates: {template_note}")

    enabled_templates = [
        entry for entry in templates if entry.get("Enabled") is True
    ]

    result: Dict[str, Any] = {
        "status": "success",
        "ca_count": len(cas),
        "template_count": len(templates),
        "enabled_template_count": len(enabled_templates),
        "vulnerable_ca_count": sum(
            1 for entry in cas if _vulnerability_names(entry)
        ),
        "vulnerable_template_count": sum(
            1 for entry in templates if _vulnerability_names(entry)
        ),
        "certificate_authorities": cas[:MAX_CAS_RETURNED],
        "certificate_templates": templates[:MAX_TEMPLATES_RETURNED],
        "vulnerable_certificate_authorities": _summarise_vulnerable(
            cas, ("CA Name", "DNS Name")
        ),
        "vulnerable_certificate_templates": _summarise_vulnerable(
            templates, ("Template Name", "Display Name")
        ),
        "cas_truncated": len(cas) > MAX_CAS_RETURNED,
        "templates_truncated": len(templates) > MAX_TEMPLATES_RETURNED,
    }

    if not cas and not ca_note:
        notes.append("No certificate authorities were found.")
    if not templates and not template_note:
        notes.append("No certificate templates were found.")
    if notes:
        result["notes"] = notes

    return result


def parse_certipy_enum_result(raw: RawCertipyEnumResult) -> Dict[str, Any]:
    """Turns a raw `certipy find` invocation into the model-facing result.

    ``status`` is ``"success"`` only when a JSON document was produced and
    parsed. Certipy exits 0 on connection/authentication failures and
    writes no JSON, so the exit code is not used to decide success.
    """
    base = {
        "target": raw.target,
        "domain": raw.domain,
        "scheme": raw.scheme,
    }

    if raw.error:
        return {**base, "status": "failed", "error": raw.error}

    if not raw.json_output:
        errors = extract_error_lines(raw.stdout) + extract_error_lines(
            raw.stderr
        )
        if errors:
            error = errors[0]
        else:
            error = (
                "certipy produced no JSON output "
                f"(exit code {raw.returncode}); check the target, "
                "credentials, and -scheme (ldap vs ldaps)"
            )
        return {**base, "status": "failed", "error": error}

    parsed = parse_certipy_json(raw.json_output)
    return {**base, **parsed}


def cap_evidence(text: str) -> str:
    """Bounds the transcript stored as evidence to MAX_EVIDENCE_CHARS."""
    if len(text) <= MAX_EVIDENCE_CHARS:
        return text
    return text[:MAX_EVIDENCE_CHARS]
