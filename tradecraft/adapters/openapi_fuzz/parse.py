"""
Pure parsing functions for openapi_fuzz output.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.openapi_fuzz.execute import RawOpenApiFuzzResult


def parse_openapi_fuzz_result(raw: RawOpenApiFuzzResult) -> Dict[str, Any]:
    if raw.error:
        return {
            "target": raw.target,
            "endpoints_tested": 0,
            "anomalies_found": 0,
            "probes": [],
            "error": raw.error,
        }

    probes: List[Dict[str, Any]] = []
    anomalies: List[Dict[str, Any]] = []

    for ep in raw.endpoints_tested:
        item = {
            "method": ep.method,
            "path": ep.path,
            "url": ep.url,
            "status_code": ep.status_code,
            "anomaly": ep.anomaly_detected,
        }
        if ep.error:
            item["error"] = ep.error
        probes.append(item)
        if ep.anomaly_detected:
            anomalies.append(item)

    return {
        "target": raw.target,
        "endpoints_tested": len(probes),
        "anomalies_found": len(anomalies),
        "anomalies": anomalies,
        "probes": probes[:15],
    }
