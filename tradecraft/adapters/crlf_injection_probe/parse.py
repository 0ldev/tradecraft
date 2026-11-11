"""
Pure parsing for crlf_injection_probe: turns a RawCrlfResult into the
model-facing result dict. No I/O.
"""
from __future__ import annotations


def parse(raw) -> dict:
    if raw.error:
        return {"target": raw.target, "parameter": raw.parameter, "error": raw.error}
    return {
        "target": raw.target,
        "parameter": raw.parameter,
        "injected_header_name": raw.injected_header_name,
        "status_code": raw.status_code,
        "injected_header_found": raw.injected_header_found,
        "injected_value_in_other_header": raw.injected_value_in_other_header,
        "vulnerable": raw.injected_header_found or raw.injected_value_in_other_header is not None,
        "error": None,
    }
