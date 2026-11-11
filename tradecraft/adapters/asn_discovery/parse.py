"""
Parsing logic for ASN discovery output.
Pure functions, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.asn_discovery.execute import RawAsnResult


def parse_result(raw: RawAsnResult) -> Dict[str, Any]:
    """Formats RawAsnResult into deduped lists of ASNs and CIDRs."""
    return {
        "asns": sorted(set(raw.asns)),
        "cidrs": sorted(set(raw.cidrs)),
    }
