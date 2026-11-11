"""
NetExec network service and domain
enumeration. Classified as destructive: false. Belongs to profile
'ad-network'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.netexec_enum import execute as nxe_execute
from tradecraft.adapters.netexec_enum import parse as nxe_parse
from tradecraft.tools.base import Tool

# Standard port per protocol, used only when NetExec's own output did not
# carry a port for a host record (it always does in practice).
_PROTOCOL_DEFAULT_PORTS = {
    "smb": 445,
    "ldap": 389,
    "winrm": 5985,
    "mssql": 1433,
    "rdp": 3389,
    "ssh": 22,
    "ftp": 21,
    "wmi": 135,
}


class NetexecEnum(Tool):
    tool_id = "netexec_enum"

    def is_available(self) -> bool:
        # The contract's required_binary is "netexec", but the adapter
        # accepts the equivalent "nxc" alias too.
        return nxe_execute.find_netexec_binary() is not None

    def run(
        self,
        target: str,
        protocol: str = "smb",
        domain: str = "",
        username: str = "",
        password: str = "",
        hashes: str = "",
        shares: bool = False,
        users: bool = False,
        groups: bool = False,
        pass_pol: bool = False,
        disks: bool = False,
        loggedon_users: bool = False,
        ccache_b64: str = "",
    ) -> Dict[str, Any]:
        raw = nxe_execute.execute(
            target=target,
            protocol=protocol,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            shares=shares,
            users=users,
            groups=groups,
            pass_pol=pass_pol,
            disks=disks,
            loggedon_users=loggedon_users,
            ccache_b64=ccache_b64,
        )
        parsed = nxe_parse.parse_netexec_enum_result(raw)

        if raw.stdout or raw.stderr:
            # Evidence keeps the uncapped view (parse_netexec_enum_result
            # caps what the model sees) plus the redacted raw transcript.
            full = nxe_parse.parse_netexec_output(raw.stdout)
            parsed["_full_evidence"] = {
                "target": raw.target,
                "protocol": raw.protocol,
                "hosts": full["hosts"],
                "unparsed_lines": full["unparsed_lines"],
                "raw_stdout": nxe_parse.redact_credentials(raw.stdout),
                "raw_stderr": raw.stderr,
            }

        return parsed

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = nxe_parse.normalize_target_host(target)
        return (host or target), full

    def extract_facts(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        hosts = result.get("hosts") or []
        if not hosts:
            return []

        facts: List[Dict[str, Any]] = []
        single_host = len(hosts) == 1
        for host in hosts:
            host_name = host.get("host") or host.get("hostname")
            if not host_name:
                continue
            port = host.get("port")
            if not port:
                port = _PROTOCOL_DEFAULT_PORTS.get(
                    host.get("protocol", result.get("protocol", "smb")),
                    _PROTOCOL_DEFAULT_PORTS["smb"],
                )

            fact: Dict[str, Any] = {
                "host": host_name,
                "port": int(port),
                "protocol": host.get("protocol") or result.get("protocol", "smb"),
            }

            if host.get("domain"):
                fact["ad_domain"] = host["domain"]
            if host.get("signing") is not None:
                fact["smb_signing"] = host["signing"]
            if host.get("smbv1") is not None:
                fact["smb_smbv1"] = host["smbv1"]
            if host.get("null_auth") is not None:
                fact["smb_null_auth"] = host["null_auth"]
            if host.get("guest_auth"):
                fact["smb_guest_auth"] = True
            if host.get("admin_access"):
                fact["smb_admin_access"] = True
            if host.get("shares_count"):
                fact["smb_shares_count"] = host["shares_count"]
            if host.get("users_count"):
                fact["smb_users_count"] = host["users_count"]
            if host.get("groups_count"):
                fact["smb_groups_count"] = host["groups_count"]

            lockout = (host.get("password_policy") or {}).get(
                "Account Lockout Threshold"
            )
            if lockout and lockout.lower() != "none":
                fact["smb_lockout_threshold"] = lockout

            # Only attach an evidence pointer when it resolves to this
            # exact host -- a multi-host run's evidence is keyed by the
            # original range/host argument, which a bare host lookup
            # won't find.
            if single_host and result.get("evidence_id"):
                fact["evidence"] = result["evidence_id"]

            facts.append(fact)
        return facts
