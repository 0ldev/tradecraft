"""
Verdict classification for the HTTP smuggling differential probe.
Pure functions, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.http_smuggling_probe.execute import (
    VARIANT_CL_TE,
    VARIANT_TE_CL,
    SmugglingProbeRun,
    VariantResult,
)

VERDICT_CL_TE = "likely_cl_te"
VERDICT_TE_CL = "likely_te_cl"
VERDICT_NONE = "no_discrepancy_detected"
VERDICT_CONN_ERR = "connection_error"

_VARIANT_VERDICT = {VARIANT_CL_TE: VERDICT_CL_TE, VARIANT_TE_CL: VERDICT_TE_CL}


def classify_variant(v: VariantResult) -> str:
    """One connection's verdict. A second non-1xx response on the same
    connection is the discrepancy signal; a single response is clean."""
    if v.status != "ok" or not v.connected:
        return VERDICT_CONN_ERR
    if v.responses_seen >= 2:
        return _VARIANT_VERDICT[v.variant]
    return VERDICT_NONE


def _variant_dict(v: VariantResult) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "variant": v.variant,
        "verdict": classify_variant(v),
        "status": v.status,
        "responses_seen": v.responses_seen,
        "status_codes": list(v.status_codes),
        "bytes_received": v.bytes_received,
        "first_response_ms": v.first_response_ms,
        "elapsed_ms": v.elapsed_ms,
    }
    if v.error:
        out["error"] = v.error
    return out


def parse(run: SmugglingProbeRun) -> Dict[str, Any]:
    """Collapses the two per-connection verdicts into one overall verdict.
    CL.TE is reported first when both indicate a discrepancy."""
    if run.error:
        return {
            "target": run.target,
            "host": run.host,
            "port": run.port,
            "ssl": run.ssl_used,
            "verdict": VERDICT_CONN_ERR,
            "error": run.error,
            "variants": [],
        }

    per_variant: List[Dict[str, Any]] = [_variant_dict(v) for v in run.variants]
    verdicts = [d["verdict"] for d in per_variant]

    if VERDICT_CL_TE in verdicts:
        overall = VERDICT_CL_TE
    elif VERDICT_TE_CL in verdicts:
        overall = VERDICT_TE_CL
    elif verdicts and all(v == VERDICT_CONN_ERR for v in verdicts):
        overall = VERDICT_CONN_ERR
    else:
        overall = VERDICT_NONE

    out: Dict[str, Any] = {
        "target": run.target,
        "host": run.host,
        "port": run.port,
        "ssl": run.ssl_used,
        "verdict": overall,
        "variants": per_variant,
    }
    if overall == VERDICT_NONE:
        out["note"] = (
            "Each probe connection returned a single response; no second "
            "response was observed on the same connection."
        )
    return out
