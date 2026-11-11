"""
Pure parsing for workflow_step_bypass_probe. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.workflow_step_bypass_probe.execute import RawWorkflowStepResult


def parse(raw: RawWorkflowStepResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "method": raw.method, "error": raw.error}

    suspected = raw.classification in ("accepted_confirmed", "accepted_unconfirmed")
    if raw.classification == "accepted_confirmed":
        summary = (
            "The later workflow step returned 2xx and included the success marker "
            "without the preceding steps being performed -- a confirmed step bypass."
        )
    elif raw.classification == "accepted_unconfirmed":
        summary = (
            "The later workflow step returned 2xx without the preceding steps being performed, "
            "but no success marker confirmed the action; verify the resulting state with a follow-up read."
        )
    elif raw.classification == "blocked":
        summary = "The later workflow step rejected the direct call with 401/403."
    elif raw.classification == "redirected":
        summary = "The later workflow step redirected the direct call; inspect the Location value."
    elif raw.classification == "rejected":
        summary = "The later workflow step rejected the direct call with a 4xx response."
    else:
        summary = "The later workflow step returned a server error."

    return {
        "target": raw.target,
        "method": raw.method,
        "status_code": raw.status_code,
        "location": raw.location or None,
        "classification": raw.classification,
        "step_bypass_suspected": suspected,
        "marker_found": raw.marker_found,
        "success_marker": raw.success_marker or None,
        "summary": summary,
        "body_excerpt": raw.body[:2000],
    }
