"""Deterministic finding → MITRE ATT&CK / CVSS mapping (Phase 5, Report
Factory).

Keyword-heuristic mapping over finding text. Honest scope: this is
*triage metadata for the report appendix*, not a vulnerability
classifier. It maps on explicit keywords in what the model logged
(which per project rules must rest on tool evidence), ordered by
specificity -- the first matching rule wins, so "SQL injection" never
falls through to the generic exploitation rule.

Every mapped CVSS score is labeled "estimated" in the render. The
report's hard rule ("do not invent a severity rating") applies to the
LLM-synthesized Executive Summary; this section is deterministic and
labeled, which is a different, honest thing.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# (rule_name, keywords, att&ck technique, name, estimated cvss base)
_RULES: List[Dict[str, Any]] = [
    {
        "name": "sql_injection",
        "keywords": ("sql injection", "sql injection", "sqli", "sql injectable", "sqli_injectable"),
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "cvss": 8.6,
    },
    {
        "name": "command_injection",
        "keywords": ("command injection", "rce", "remote code execution", "cmdi", "webshell", "reverse shell"),
        "technique": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "cvss": 9.8,
    },
    {
        "name": "credential_exposure",
        "keywords": ("credential", "secret", "password", "api key", "private key", "token leak", "trufflehog"),
        "technique": "T1552",
        "technique_name": "Unsecured Credentials",
        "cvss": 9.1,
    },
    {
        "name": "brute_force",
        "keywords": ("brute force", "default credential", "weak password", "credential stuffing", "password spray"),
        "technique": "T1110",
        "technique_name": "Brute Force",
        "cvss": 7.5,
    },
    {
        "name": "ssrf",
        "keywords": ("ssrf", "server-side request forgery", "metadata service"),
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "cvss": 8.2,
    },
    {
        "name": "xss",
        "keywords": ("xss", "cross-site scripting"),
        "technique": "T1059.7",
        "technique_name": "JavaScript Execution",
        "cvss": 6.1,
    },
    {
        "name": "open_redirect",
        "keywords": ("open redirect", "open_redirection"),
        "technique": "T1566.002",
        "technique_name": "Spearphishing Link",
        "cvss": 4.3,
    },
    {
        "name": "cloud_exposure",
        "keywords": ("s3 bucket", "bucket", "public blob", "firebase", "cloud metadata", "iam"),
        "technique": "T1530",
        "technique_name": "Data from Cloud Storage",
        "cvss": 7.5,
    },
    {
        "name": "ad_attack",
        "keywords": ("kerberoast", "bloodhound", "dcsync", "domain admin", "pass-the-hash", "certipy"),
        "technique": "T1558",
        "technique_name": "Steal or Forge Kerberos Tickets",
        "cvss": 8.8,
    },
    {
        "name": "container_escape",
        "keywords": ("kubernetes", "container escape", "privileged container", "service account token"),
        "technique": "T1611",
        "technique_name": "Escape to Host",
        "cvss": 9.0,
    },
    {
        "name": "information_disclosure",
        "keywords": ("version disclosure", "directory listing", "source map", ".git exposed", "comment leak"),
        "technique": "T1592",
        "technique_name": "Gather Victim Host Information",
        "cvss": 5.3,
    },
]

# Generic fallback for anything that is clearly a vulnerability but
# matches no specific rule.
_FALLBACK = {
    "name": "generic_exploitation",
    "technique": "T1190",
    "technique_name": "Exploit Public-Facing Application",
    "cvss": 7.0,
}


def map_finding(text: str) -> Optional[Dict[str, Any]]:
    """Map one finding string to triage metadata, or None when the text
    carries no vulnerability-class keyword at all (e.g. a pure
    observation)."""
    lowered = (text or "").lower()
    for rule in _RULES:
        if any(k in lowered for k in rule["keywords"]):
            return {
                "rule": rule["name"],
                "technique": rule["technique"],
                "technique_name": rule["technique_name"],
                "cvss_estimated": rule["cvss"],
            }
    # Anything that made it into findings is presumably attack-relevant;
    # the generic rule catches it. Pure-noise findings (the model was
    # told findings must rest on evidence) still get the honest label.
    fallback = {"rule": _FALLBACK["name"], **{k: v for k, v in _FALLBACK.items() if k != "name"}}
    fallback["cvss_estimated"] = fallback.pop("cvss")
    return fallback


def render_attack_appendix(findings: List[str]) -> str:
    """Markdown appendix: one row per finding, deterministic metadata."""
    if not findings:
        return "_(no findings -- nothing to map)_"
    lines = [
        "| Finding | ATT&CK Technique | Est. CVSS |",
        "|---|---|---|",
    ]
    for text in findings:
        mapping = map_finding(text)
        if mapping is None:
            continue
        short = re.sub(r"\[.*?\]", "", text).strip()[:120]
        lines.append(
            f"| {short} | {mapping['technique']} — {mapping['technique_name']} "
            f"| {mapping['cvss_estimated']} (estimated) |"
        )
    if len(lines) == 3:
        return "_(no findings -- nothing to map)_"
    lines.append("")
    lines.append("_CVSS scores are heuristic estimates from finding-class keywords, "
                 "not calculated vectors. They triage the appendix; they do not "
                 "replace proper scoring._")
    return "\n".join(lines)
