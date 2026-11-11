"""
Pure parsing/diffing for nosql_injection_probe. No I/O here.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def is_anomalous(baseline, probe) -> bool:
    """A probe is anomalous relative to baseline if its status code
    differs AND its body length differs by more than 5 characters (a
    pure status-code-only difference, or a pure whitespace-shaped body
    difference, is too weak a signal alone -- both together is the bar).
    Also flags if the probe succeeded (2xx) while the baseline did not,
    or vice versa, regardless of body-length delta -- an auth/query
    outcome flip is the strongest signal."""
    if baseline is None or baseline.error or probe.error:
        return False
    baseline_ok = 200 <= baseline.status_code < 300
    probe_ok = 200 <= probe.status_code < 300
    if baseline_ok != probe_ok:
        return True
    length_delta = abs(probe.body_length - baseline.body_length)
    return baseline.status_code != probe.status_code and length_delta > 5


def parse(raw) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "field": raw.field, "error": raw.error}

    baseline = raw.baseline_response
    anomalies = []
    for probe in raw.probes:
        if is_anomalous(baseline, probe):
            anomalies.append({
                "operator": probe.operator,
                "baseline_status": baseline.status_code if baseline else None,
                "probe_status": probe.status_code,
                "baseline_body_length": baseline.body_length if baseline else None,
                "probe_body_length": probe.body_length,
            })

    return {
        "target": raw.target,
        "field": raw.field,
        "baseline_status": baseline.status_code if baseline else None,
        "tested_operators": [p.operator for p in raw.probes],
        "anomalous_operators": [a["operator"] for a in anomalies],
        "anomalies": anomalies,
        "vulnerable": len(anomalies) > 0,
        "error": None,
    }
