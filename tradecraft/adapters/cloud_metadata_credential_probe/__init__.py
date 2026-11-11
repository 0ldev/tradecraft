"""
cloud_metadata_credential_probe adapter package.
"""
from __future__ import annotations

from tradecraft.adapters.cloud_metadata_credential_probe.execute import execute
from tradecraft.adapters.cloud_metadata_credential_probe.parse import parse

__all__ = ["execute", "parse"]
