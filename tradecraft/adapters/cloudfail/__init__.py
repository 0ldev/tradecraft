"""Cloudfail Cloudflare origin unmasking adapter."""
from tradecraft.adapters.cloudfail.execute import (
    RawCloudfailResult,
    build_argv,
    execute,
    normalize_target,
)
from tradecraft.adapters.cloudfail.parse import parse_cloudfail_output

__all__ = [
    "RawCloudfailResult",
    "build_argv",
    "execute",
    "normalize_target",
    "parse_cloudfail_output",
]
