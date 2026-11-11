"""
Parsing logic for JWT alg=none signature bypass differential testing.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


def parse_result(baseline_status: Optional[int], forged_status: Optional[int]) -> Dict[str, Any]:
    vulnerable = baseline_status in (401, 403) and forged_status == 200
    return {
        "vulnerable": vulnerable,
        "baseline_status": baseline_status,
        "forged_status": forged_status,
    }
