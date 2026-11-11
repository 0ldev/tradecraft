"""
Parsing logic for netexec_enum network enumeration output.

Pure functions, no I/O, no subprocess calls.

Every output format handled here was checked against the real NetExec
1.5.1 source (nxc/logger.py's row formatter and the per-protocol
``logger.display``/``highlight`` call sites) and against real captured
output from ``netexec smb``, not guessed. Two facts that drove the
design:

* NetExec prefixes every line with fixed, space-separated columns:
  ``<module:<24> <host:<15> <port:<6> <hostname:<16> <msg>``. An absent
  hostname is printed as the literal ``NONE``, never as a blank column,
  so every data line always has five whitespace-separated leading
  fields. That is what ``_ROW_REGEX`` relies on.
* Section headers are not all the same severity marker. Shares and disks
  are ``[*]`` info lines; the password-policy header is ``[+]``; user and
  group tables have no marker at all -- they start with a ``-Username-``/
  ``-Group-`` header row. The state machine below keys off the real
  shapes, not one assumed marker.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

_ANSI_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# <module> <host> <port> <hostname> <message> -- one space minimum between
# fields; NetExec pads to fixed widths, but overflowing values are not
# truncated, so match on whitespace rather than fixed offsets.
_ROW_REGEX = re.compile(
    r"^(?P<protocol>\S+)\s+(?P<host>\S+)\s+(?P<port>\d+)\s+"
    r"(?P<hostname>\S+)\s+(?P<message>.*)$"
)

_MARKER_REGEX = re.compile(r"^\[(?P<marker>[+\-*!])\]\s?(?P<text>.*)$")

# domain\user:secret[ (Guest|Pwn3d!)] -- the "secret" is whatever the
# operator supplied, echoed back by NetExec; never kept in parsed output.
_AUTH_REGEX = re.compile(
    r"^(?P<domain>[^\\\s]+)\\(?P<user>[^:]*):(?P<secret>.*?)"
    r"(?:\s+\((?P<note>[^)]*)\))?$"
)

_BANNER_TOKEN_REGEX = {
    "domain": re.compile(r"\(domain:([^)]*)\)"),
    "signing": re.compile(r"\(signing:([^)]*)\)"),
    "smbv1": re.compile(r"\(SMBv1:([^)]*)\)"),
    "null_auth": re.compile(r"\(Null Auth:([^)]*)\)"),
}

_LOGGEDON_REGEX = re.compile(r"^\S+\\\S+\s+logon_server:\s*\S+")

# NetExec's own table layouts (confirmed in the installed source):
#   shares:  {'Share':<15} {'Permissions':<22} {'Remark'}
#   users:   {'-Username-':<30}{'-Last PW Set-':<20}{'-BadPW-':<8|9}{'-Description-'}
#   groups:  {'-Group-':<40} {'-Members-':<9} {'-Description-'}
_SHARE_NAME_WIDTH = 15
_SHARE_PERMS_WIDTH = 22
_USER_NAME_WIDTH = 30
_GROUP_NAME_WIDTH = 40

# The shares table's own header row is not marker-prefixed, so it would
# otherwise be read as a share named "Share". Matches the real header
# NetExec prints: "Share           Permissions            Remark".
_SHARE_HEADER_REGEX = re.compile(
    r"^Share\s+Permissions\s+Remark\s*$", re.IGNORECASE
)

MAX_USERS_RETURNED = 50
MAX_SHARES_RETURNED = 50
MAX_GROUPS_RETURNED = 50
MAX_DISKS_RETURNED = 20
MAX_LOGGEDON_RETURNED = 25
MAX_ERRORS_RETURNED = 10
MAX_NOTES_RETURNED = 20


@dataclass
class RawNetexecEnumResult:
    target: str = ""
    protocol: str = "smb"
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


@dataclass
class _HostRecord:
    host: str
    port: int
    protocol: str
    hostname: Optional[str] = None
    banner: Optional[str] = None
    os: Optional[str] = None
    domain: Optional[str] = None
    signing: Optional[bool] = None
    smbv1: Optional[bool] = None
    null_auth: Optional[bool] = None
    auth_success: bool = False
    auth_user: Optional[str] = None
    guest_auth: bool = False
    admin_access: bool = False
    shares: List[Dict[str, str]] = field(default_factory=list)
    users: List[Dict[str, str]] = field(default_factory=list)
    groups: List[Dict[str, str]] = field(default_factory=list)
    password_policy: Dict[str, str] = field(default_factory=dict)
    disks: List[str] = field(default_factory=list)
    loggedon_users: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def strip_ansi(text: str) -> str:
    """Removes ANSI color escape sequences."""
    return _ANSI_REGEX.sub("", text)


def normalize_target_host(target: str) -> str:
    """Extracts the raw host/CIDR from a target string.

    A URL's hostname is kept; an explicit ``host:port`` suffix is dropped
    (NetExec picks the port per protocol). IPv6 brackets are unwrapped.
    A CIDR range is preserved as-is -- NetExec accepts ranges directly.
    """
    cleaned = (target or "").strip()
    if not cleaned:
        return ""
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        return (parsed.hostname or "").strip()
    if cleaned.startswith("["):
        end = cleaned.find("]")
        if end != -1:
            return cleaned[1:end]
    # A single colon with a numeric suffix is host:port; more than one
    # colon is IPv6 and must not be split.
    if cleaned.count(":") == 1:
        host, _, maybe_port = cleaned.partition(":")
        if maybe_port.isdigit():
            return host.strip()
    return cleaned.strip("/[] ")


def parse_host_port(target: str, default_port: int = 445) -> Tuple[str, int]:
    """Parses host and port from a target string, falling back to
    ``default_port`` (the protocol's standard port) when none is given."""
    host = normalize_target_host(target)
    cleaned = (target or "").strip()
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        if parsed.port:
            return host, parsed.port
    elif cleaned.count(":") == 1:
        _, _, maybe_port = cleaned.partition(":")
        if maybe_port.isdigit():
            return host, int(maybe_port)
    return host, default_port


def redact_credentials(text: str) -> str:
    """Replaces the echoed credential on NetExec auth lines with
    ``<redacted>`` before the raw transcript is persisted as evidence.

    NetExec prints ``domain\\user:password`` when authentication is
    attempted. That is the operator's own supplied secret, not a target
    discovery, and there is no reason to write it to disk a second time.
    """
    out_lines = []
    for line in text.splitlines():
        match = _ROW_REGEX.match(line)
        if not match:
            out_lines.append(line)
            continue
        message = match.group("message")
        marker = _MARKER_REGEX.match(message)
        if not marker or marker.group("marker") != "+":
            out_lines.append(line)
            continue
        auth = _AUTH_REGEX.match(marker.group("text"))
        if not auth or not auth.group("secret"):
            out_lines.append(line)
            continue
        redacted_message = message.replace(
            auth.group("secret"), "<redacted>", 1
        )
        out_lines.append(
            line[: match.start("message")] + redacted_message
        )
    return "\n".join(out_lines)


def _parse_bool(value: str) -> Optional[bool]:
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def _record_for(
    records: Dict[str, _HostRecord], host: str, port: int, protocol: str, hostname: Optional[str]
) -> _HostRecord:
    record = records.get(host)
    if record is None:
        record = _HostRecord(host=host, port=port, protocol=protocol, hostname=hostname)
        records[host] = record
    else:
        if hostname and not record.hostname:
            record.hostname = hostname
        if not record.port:
            record.port = port
    return record


def _apply_banner(record: _HostRecord, banner: str) -> None:
    record.banner = banner
    record.os = banner.split(" (", 1)[0].strip() or None
    for attr, regex in _BANNER_TOKEN_REGEX.items():
        token = regex.search(banner)
        if not token:
            continue
        if attr == "domain":
            record.domain = token.group(1).strip() or None
        else:
            parsed = _parse_bool(token.group(1))
            if parsed is not None:
                setattr(record, attr, parsed)


def _apply_auth(record: _HostRecord, text: str) -> None:
    match = _AUTH_REGEX.match(text)
    if not match:
        return
    record.auth_success = True
    if match.group("domain"):
        record.domain = match.group("domain")
    record.auth_user = match.group("user") or None
    note = (match.group("note") or "").lower()
    if "guest" in note:
        record.guest_auth = True
    if "pwn3d" in note:
        record.admin_access = True
    elif "pwn3d" in text.lower():
        record.admin_access = True


def _split_name_and_detail(message: str, name_width: int) -> Dict[str, str]:
    name = message[:name_width].strip()
    detail = message[name_width:].strip()
    out = {"name": name}
    if detail:
        out["detail"] = detail
    return out


def parse_netexec_output(output: str) -> Dict[str, Any]:
    """Parses NetExec output lines into one record per responsive host.

    Returns ``{"hosts": [record, ...], "unparsed_lines": int}``. A record
    holds only what NetExec actually reported; anything not recognised as
    a known shape is counted as unparsed rather than guessed at.
    """
    clean_text = strip_ansi(output or "")
    records: Dict[str, _HostRecord] = {}
    modes: Dict[str, Optional[str]] = {}
    unparsed_lines = 0

    for raw_line in clean_text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        row = _ROW_REGEX.match(line)
        if not row:
            unparsed_lines += 1
            continue

        host = row.group("host")
        port = int(row.group("port"))
        hostname = row.group("hostname")
        if hostname.upper() == "NONE":
            hostname = None
        record = _record_for(
            records, host, port, row.group("protocol").lower(), hostname
        )
        mode = modes.get(host)

        message = row.group("message").strip()
        if not message:
            continue

        marker = _MARKER_REGEX.match(message)
        if marker:
            marker_char = marker.group("marker")
            text = marker.group("text").strip()
            lowered = text.lower()

            if lowered.startswith("enumerated shares"):
                modes[host] = "shares"
                continue
            if lowered.startswith("enumerated disks"):
                modes[host] = "disks"
                continue
            if lowered.startswith("dumping password info for domain"):
                modes[host] = "pass_pol"
                _, _, domain = text.partition(":")
                if domain.strip():
                    record.password_policy["domain"] = domain.strip()
                continue
            if lowered.startswith("enumerated") and "users:" in lowered:
                # Trailing summary line -- ends the user table.
                modes[host] = None
                continue
            if marker_char == "-":
                record.errors.append(text)
                modes[host] = None
                continue
            if marker_char == "+" and _AUTH_REGEX.match(text):
                _apply_auth(record, text)
                modes[host] = None
                continue
            if record.banner is None and ("(name:" in text or "(domain:" in text):
                _apply_banner(record, text)
                modes[host] = None
                continue
            # Any other marker is informational; keep it, end the section.
            record.notes.append(f"[{marker_char}] {text}")
            modes[host] = None
            continue

        # --- non-marker data rows -------------------------------------
        if message.startswith("-Username-"):
            modes[host] = "users"
            continue
        if message.startswith("-Group-"):
            modes[host] = "groups"
            continue

        if _LOGGEDON_REGEX.match(message):
            record.loggedon_users.append(message)
            continue

        if mode == "shares":
            if _SHARE_HEADER_REGEX.match(message):
                continue
            name = message[:_SHARE_NAME_WIDTH].strip()
            if not name or set(name) <= {"-"}:
                continue
            perms = message[
                _SHARE_NAME_WIDTH + 1 : _SHARE_NAME_WIDTH + 1 + _SHARE_PERMS_WIDTH
            ].strip()
            remark = message[
                _SHARE_NAME_WIDTH + 1 + _SHARE_PERMS_WIDTH + 1 :
            ].strip()
            share: Dict[str, str] = {"name": name}
            if perms:
                share["permissions"] = perms
            if remark:
                share["remark"] = remark
            record.shares.append(share)

        elif mode == "users":
            if set(message.strip()) <= {"-"}:
                continue
            user = _split_name_and_detail(message, _USER_NAME_WIDTH)
            if user.get("name"):
                record.users.append(user)

        elif mode == "groups":
            if set(message.strip()) <= {"-"}:
                continue
            group = _split_name_and_detail(message, _GROUP_NAME_WIDTH)
            if group.get("name"):
                record.groups.append(group)

        elif mode == "pass_pol":
            if ":" in message and not set(message.strip()) <= {":"}:
                key, _, value = message.partition(":")
                record.password_policy[key.strip()] = value.strip()

        elif mode == "disks":
            disk = message.strip()
            if disk:
                record.disks.append(disk)

    hosts = []
    for record in records.values():
        hosts.append(
            {
                "host": record.host,
                "port": record.port,
                "protocol": record.protocol,
                "hostname": record.hostname,
                "banner": record.banner,
                "os": record.os,
                "domain": record.domain,
                "signing": record.signing,
                "smbv1": record.smbv1,
                "null_auth": record.null_auth,
                "auth_success": record.auth_success,
                "auth_user": record.auth_user,
                "guest_auth": record.guest_auth,
                "admin_access": record.admin_access,
                "shares": record.shares,
                "shares_count": len(record.shares),
                "users": record.users,
                "users_count": len(record.users),
                "groups": record.groups,
                "groups_count": len(record.groups),
                "password_policy": record.password_policy,
                "disks": record.disks,
                "loggedon_users": record.loggedon_users,
                "errors": record.errors,
                "notes": record.notes,
            }
        )
    hosts.sort(key=lambda item: (item["host"], item["port"]))
    return {"hosts": hosts, "unparsed_lines": unparsed_lines}


def _cap_list(items: List[Any], limit: int) -> Tuple[List[Any], bool]:
    return items[:limit], len(items) > limit


def _cap_host(host: Dict[str, Any]) -> Dict[str, Any]:
    capped = dict(host)
    for key, limit in (
        ("shares", MAX_SHARES_RETURNED),
        ("users", MAX_USERS_RETURNED),
        ("groups", MAX_GROUPS_RETURNED),
        ("disks", MAX_DISKS_RETURNED),
        ("loggedon_users", MAX_LOGGEDON_RETURNED),
        ("errors", MAX_ERRORS_RETURNED),
        ("notes", MAX_NOTES_RETURNED),
    ):
        value, truncated = _cap_list(capped.get(key, []), limit)
        capped[key] = value
        if truncated:
            capped[f"{key}_truncated"] = True
    return capped


def parse_netexec_enum_result(raw: RawNetexecEnumResult) -> Dict[str, Any]:
    """Turns a raw NetExec invocation into the model-facing result dict.

    ``status`` is:
    * ``"failed"``      -- the process itself failed (error/timeout/
                           non-zero exit with no host output).
    * ``"no_response"`` -- NetExec ran cleanly but printed no host block.
      NetExec silently skips unreachable hosts, so this is the normal
      shape for "nothing listening", not a tool error.
    * ``"success"``     -- at least one host block was parsed.
    """
    if raw.error:
        return {
            "target": raw.target,
            "protocol": raw.protocol,
            "status": "failed",
            "hosts_found": 0,
            "hosts": [],
            "error": raw.error,
        }

    parsed = parse_netexec_output(raw.stdout)
    hosts = [_cap_host(host) for host in parsed["hosts"]]

    result: Dict[str, Any] = {
        "target": raw.target,
        "protocol": raw.protocol,
        "hosts_found": len(hosts),
        "hosts": hosts,
    }

    if hosts:
        result["status"] = "success"
    elif raw.returncode != 0:
        stderr_tail = (raw.stderr or "").strip().splitlines()
        result["status"] = "failed"
        result["error"] = (
            stderr_tail[-1]
            if stderr_tail
            else f"netexec exited with return code {raw.returncode} and no host output"
        )
    else:
        result["status"] = "no_response"
        result["note"] = (
            f"netexec printed no host output -- no responsive {raw.protocol} "
            "service was found on the target(s). NetExec silently skips "
            "unreachable hosts, so this is not an execution failure."
        )

    if parsed["unparsed_lines"]:
        result["unparsed_lines"] = parsed["unparsed_lines"]
    return result
