"""
The cracked secret is reported in full, never redacted: for this tool the
secret is the finding itself, not a credential to protect.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.jwt_crack import execute as jwt_execute
from tradecraft.adapters.jwt_crack import parse as jwt_parse
from tradecraft.tools.base import Tool


class JwtCrack(Tool):
    tool_id = "jwt_crack"

    def run(self, jwt: str, wordlist: str = "") -> Dict[str, Any]:
        raw = jwt_execute.execute(jwt=jwt, wordlist=wordlist)
        return jwt_parse.parse_jwt_crack_result(raw)
