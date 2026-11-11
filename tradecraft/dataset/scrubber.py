"""
Deterministic target, hostname, and IPv4 scrubber for dataset anonymization.

Replaces the engagement's primary target, discovered subdomains/hosts, and IPv4
addresses with consistent RFC 2606 / RFC 5737 placeholders (`target.example`,
`sub1.target.example`, `198.51.100.1`, ...) across prompts, reasoning, tool call
arguments, and tool results so finetuned models learn tradecraft rather than
memorizing specific engagement targets.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Set, Tuple
from urllib.parse import urlsplit

# Markers from tradecraft/memory/cross_engagement.py and
# tradecraft/execution/run_dir.py::load_seed_context.
_SEED_BLOCK_RE = re.compile(
    r"--- (?:Cross-engagement memory for root domain|Known from a prior engagement).*?\n---",
    re.DOTALL,
)
_SEED_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SEED_HOSTNAME_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE
)
_SEED_RUN_ID_RE = re.compile(r"\b\d{8}T\d{6}Z_[0-9a-f]{6}\b")


def extract_seed_identifiers(system_prompt: str) -> Tuple[Set[str], Set[str], Set[str]]:
    """Extracts hostnames/IPv4s/run ids from any seed-context block in a system prompt."""
    hosts: Set[str] = set()
    ips: Set[str] = set()
    run_ids: Set[str] = set()
    for block in _SEED_BLOCK_RE.findall(system_prompt or ""):
        ips.update(_SEED_IPV4_RE.findall(block))
        run_ids.update(_SEED_RUN_ID_RE.findall(block))
        for host in _SEED_HOSTNAME_RE.findall(block):
            host_lower = host.lower()
            if host_lower not in ips:
                hosts.add(host_lower)
    return hosts, ips, run_ids


def _extract_hostname(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlsplit(raw)
        return (parsed.hostname or raw).strip().lower()
    if "/" in raw or ":" in raw:
        parsed = urlsplit(f"https://{raw}")
        return (parsed.hostname or raw).strip().lower()
    return raw.lower()


def build_scrub_map(
    target: str,
    discovered_hosts: Iterable[str] = (),
    discovered_ips: Iterable[str] = (),
    seed_run_ids: Iterable[str] = (),
) -> List[Tuple[re.Pattern[str], str]]:
    """Builds an ordered list of (regex_pattern, replacement) pairs, longest-first.
    Fold any `extract_seed_identifiers()` output into `discovered_hosts`/`discovered_ips`
    yourself; `seed_run_ids` get their own placeholder since they're neither."""
    apex = _extract_hostname(target)
    all_hosts = sorted(
        {_extract_hostname(h) for h in discovered_hosts if _extract_hostname(h)},
    )
    all_ips = sorted({ip.strip() for ip in discovered_ips if ip and ip.strip()})

    replacements: Dict[str, str] = {}

    if apex and apex not in all_ips:
        replacements[apex] = "target.example"
        # Also map bare label if apex has a TLD (e.g. "examplepaint" in "examplepaint.com.br")
        sub_idx = 1
        for host in all_hosts:
            if host == apex or host in all_ips:
                continue
            if host.endswith("." + apex):
                replacements[host] = f"sub{sub_idx}.target.example"
                sub_idx += 1
            else:
                replacements[host] = f"host{sub_idx}.target.example"
                sub_idx += 1
    else:
        host_idx = 1
        for host in all_hosts:
            if host in all_ips:
                continue
            replacements[host] = f"host{host_idx}.target.example"
            host_idx += 1

    for idx, ip in enumerate(all_ips, start=1):
        octet = ((idx - 1) % 254) + 1
        replacements[ip] = f"198.51.100.{octet}"

    for idx, run_id in enumerate(sorted({r.strip() for r in seed_run_ids if r and r.strip()}), start=1):
        replacements[run_id] = f"seed-run-{idx}"

    # Sort longest-first so subdomains are replaced before their parent apex domain
    ordered_keys = sorted(replacements.keys(), key=len, reverse=True)
    patterns: List[Tuple[re.Pattern[str], str]] = []
    for key in ordered_keys:
        if not key:
            continue
        pat = re.compile(re.escape(key), re.IGNORECASE)
        patterns.append((pat, replacements[key]))
    return patterns


def apply_scrub_map(value: Any, patterns: List[Tuple[re.Pattern[str], str]]) -> Any:
    """Recursively applies `patterns` across strings, lists, and dicts."""
    if not patterns:
        return value
    if isinstance(value, str):
        out = value
        for pat, repl in patterns:
            out = pat.sub(repl, out)
        return out
    if isinstance(value, list):
        return [apply_scrub_map(item, patterns) for item in value]
    if isinstance(value, dict):
        return {
            apply_scrub_map(k, patterns) if isinstance(k, str) else k: apply_scrub_map(v, patterns)
            for k, v in value.items()
        }
    return value
