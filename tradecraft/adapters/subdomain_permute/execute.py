"""
Raw generation for subdomain_permute: builds subdomain name candidates from a
built-in keyword list, optional seed labels, and fixed separator patterns.
Makes no network calls. No parsing here -- parse.py's job.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import List

KEYWORDS = [
    "dev", "development", "stg", "staging", "staging2", "test", "qa",
    "uat", "demo", "sandbox", "preview", "beta", "alpha", "canary",
    "api", "api2", "apiv2", "rest", "graphql", "gateway", "gw",
    "admin", "administrator", "portal", "dashboard", "console", "panel",
    "internal", "intranet", "private", "secure", "vpn", "corp",
    "backend", "backoffice", "manage", "management",
    "app", "app2", "mobile", "m", "web", "web2",
    "auth", "sso", "login", "login2", "oauth", "idp",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo",
    "files", "static", "assets", "cdn", "media", "uploads", "storage",
    "mail", "smtp", "webmail", "autodiscover",
    "monitor", "monitoring", "status", "health", "metrics", "grafana",
    "jenkins", "ci", "cd", "build", "deploy",
    "old", "legacy", "v1", "v2", "v3", "new",
    "support", "help", "docs", "wiki",
    "partner", "partners", "vendor", "b2b",
]  # ~90 entries, trimmed/extended freely -- not sacred, just a start

SEPARATOR_PATTERNS = ["{kw}", "{kw}-", "{kw}.", "{kw}1", "{kw}2", "{kw}3"]


@dataclass
class RawPermuteResult:
    target: str = ""
    candidates: List[str] = field(default_factory=list)
    error: str = ""


def normalize_apex(raw: str) -> str:
    """Reduce a URL, host, or apex string to a bare lowercase apex domain."""
    s = raw.strip().lower()
    if "://" in s:
        s = urllib.parse.urlsplit(s).hostname or ""
    else:
        s = s.split("/", 1)[0].split(":", 1)[0]
    return s.strip(".")


def _valid_hostname(name: str) -> bool:
    labels = name.split(".")
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return False
    return True


def generate_candidates(target: str, seed_subdomains: str = "") -> RawPermuteResult:
    apex = normalize_apex(target)
    if not apex:
        return RawPermuteResult(target=target, error="target is required (an apex domain, e.g. 'example.com')")

    keywords = list(KEYWORDS)
    if seed_subdomains:
        for entry in seed_subdomains.split(","):
            name = entry.strip().lower().strip(".")
            if "." not in name:
                continue
            label, _, domain = name.partition(".")
            # Only trust seeds that actually belong to this apex.
            if domain != apex or not label or label in keywords:
                continue
            keywords.append(label)

    candidates = set()
    for kw in keywords:
        for pattern in SEPARATOR_PATTERNS:
            candidate = f"{pattern.format(kw=kw)}.{apex}"
            # Some separator patterns (a trailing '-' or '.') produce names
            # that are not valid hostnames; drop those rather than resolve junk.
            if _valid_hostname(candidate):
                candidates.add(candidate)

    return RawPermuteResult(target=apex, candidates=sorted(candidates))
