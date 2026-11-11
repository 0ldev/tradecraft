from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.adapters.php_cgi_arg_injection_probe import execute as php_cgi_execute
from tradecraft.adapters.php_cgi_arg_injection_probe import parse as php_cgi_parse
from tradecraft.tools.base import Tool


class PhpCgiArgInjectionProbe(Tool):
    tool_id = "php_cgi_arg_injection_probe"

    def run(
        self,
        target: str,
        path: Optional[str] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        raw = php_cgi_execute.execute(
            target=target,
            path=path,
            timeout=timeout,
        )
        return php_cgi_parse.parse_php_cgi_result(raw)
