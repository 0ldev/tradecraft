from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.adapters.drupal_jsonapi_sqli_probe import execute as drupal_execute
from tradecraft.adapters.drupal_jsonapi_sqli_probe import parse as drupal_parse
from tradecraft.tools.base import Tool


class DrupalJsonapiSqliProbe(Tool):
    tool_id = "drupal_jsonapi_sqli_probe"

    def run(
        self,
        target: str,
        path: str = "/jsonapi/node/article",
        host_header: Optional[str] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        raw = drupal_execute.execute(
            target=target,
            path=path,
            host_header=host_header,
            timeout=timeout,
        )
        return drupal_parse.parse_drupal_sqli_result(raw)
