"""
Container-isolation misconfiguration enumeration from inside a pod that
is already reached via some other foothold. One `kubectl exec` runs one
fixed read-only script in the container and reports the mounted
service-account token, the Docker socket's presence and writability,
and the effective Linux capability set. Classified as destructive: false
(reads and reports only; changes nothing in the container). Belongs to
profiles 'kubernetes' and 'post-exploitation'.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.pod_exec_enum import execute as pee_execute
from tradecraft.adapters.pod_exec_enum import parse as pee_parse
from tradecraft.tools.base import Tool


class PodExecEnum(Tool):
    tool_id = "pod_exec_enum"

    def run(
        self,
        server: str,
        token: str,
        namespace: str,
        pod: str,
        container: str = "",
    ) -> Dict[str, Any]:
        raw = pee_execute.execute(
            server=server,
            token=token,
            namespace=namespace,
            pod=pod,
            container=container,
        )
        return pee_parse.parse_pod_exec_result(raw)
