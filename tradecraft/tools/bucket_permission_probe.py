"""
Non-destructive: read-only list checks, no object is ever written.
Belongs to profiles 'web' and 'cloud'. The destructive counterpart is
bucket_permission_exploit.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.bucket_permission_probe import execute as bpp_execute
from tradecraft.adapters.bucket_permission_probe import parse as bpp_parse
from tradecraft.tools.base import Tool


class BucketPermissionProbe(Tool):
    tool_id = "bucket_permission_probe"

    def run(
        self,
        provider: str,
        buckets: str,
        azure_containers: str = "",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = bpp_execute.execute(
            provider=provider,
            buckets=buckets,
            azure_containers=azure_containers,
            timeout=timeout,
        )
        return bpp_parse.parse_bucket_permission_result(raw)
