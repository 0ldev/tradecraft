"""
Generates a Java gadget-chain payload with ysoserial and fires it at up
to 4 candidate injection points. Classified as destructive: true (it
delivers a working RCE payload against a live target). See
tradecraft/adapters/deserialization_probe/ for why this tool reports no
synchronous "vulnerable" verdict.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.deserialization_probe import execute as deser_execute
from tradecraft.adapters.deserialization_probe import parse as deser_parse
from tradecraft.tools.base import Tool


class DeserializationProbe(Tool):
    tool_id = "deserialization_probe"

    def is_available(self) -> bool:
        # required_binary="java" alone would report available even when
        # ysoserial.jar itself isn't installed -- same gap phpggc's own
        # is_available() already guards against for its script dependency.
        if not super().is_available():
            return False
        return deser_execute.find_jar() is not None

    def run(
        self,
        target: str,
        oob_domain: str,
        payload_type: str = "",
        carrier: str = "",
    ) -> Dict[str, Any]:
        raw = deser_execute.execute(
            target=target,
            oob_domain=oob_domain,
            payload_type=payload_type,
            carrier=carrier,
        )
        parsed = deser_parse.parse_result(raw)

        if not parsed.get("error"):
            # Always keep full evidence of what was sent, regardless of
            # outcome -- this tool can never itself confirm or rule out
            # execution (see parse.py's docstring), so the one thing it
            # owes a later reviewer is an exact record of the attempt:
            # same "never hide what was done" principle webshell_upload
            # and auth_bootstrap already apply to their own destructive
            # actions.
            parsed["_full_evidence"] = {
                "target": parsed.get("target"),
                "gadget": parsed.get("gadget"),
                "oob_domain": parsed.get("oob_domain"),
                "attempted_carriers": parsed.get("attempted_carriers"),
                "attempts": parsed.get("attempts"),
                "payload_b64": raw.payload_b64,
            }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = deser_parse.parse_host_port(target)
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        # No synchronous "vulnerable" signal exists for this tool (see
        # parse.py's own docstring) -- only a "this host:port already had
        # a deserialization attempt sent" marker, the same per-class
        # tested-field convention the sqli_tested/xss_tested/cmdi_tested
        # fields established. A confirmed hit is the model's own job to
        # log via log_finding once a later interactsh poll matches this
        # call's own oob_domain and timing.
        target = params.get("target", "")
        if not target or result.get("error"):
            return []
        host, port = deser_parse.parse_host_port(target)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "java_deserialization_tested": True,
            "java_deserialization_oob_domain": result.get("oob_domain"),
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
