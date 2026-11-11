"""
Parsing logic for pacu_enum: read-only AWS enumeration via Pacu.

Pure functions, no I/O, no subprocess calls.

Every output shape handled here was checked against the real Pacu 1.7.0
module source and against real Pacu 1.7.0 output captured on CT 115:

* ``iam__enum_permissions`` ends with a ``MODULE SUMMARY`` block whose
  lines are ``"<n> Confirmed permissions for user: <name>."`` (single
  key) or ``"<n> Confirmed permissions for <m> user(s)."`` (its
  ``--all-users`` form), plus the matching Unconfirmed/role lines.
* ``iam__privesc_scan --scan-only`` prints ``"  CONFIRMED: <method>"`` /
  ``"  POTENTIAL: <method>"`` and, with ``--scan-only``, a final
  ``"  Scan Complete"``; ``"  None found"`` is the clean empty case.
* ``s3__download_bucket --names-only`` prints ``Found bucket "<name>"``
  lines and a summary of ``"<n> total buckets found."`` /
  ``"<m> buckets found with read permissions."``.

The credentials this call used are redacted from every persisted field;
Pacu itself echoes an access key ID into its own session log, so the tool
layer also keeps the whole run inside a disposable HOME directory.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

MAX_BUCKET_NAMES_RETURNED = 50
MAX_OBJECTS_RETURNED = 100
MAX_SUMMARY_LINES_RETURNED = 20
MAX_ERROR_CHARS = 500
MAX_EVIDENCE_CHARS = 2_000_000

_CLIENT_ERROR_REGEX = re.compile(
    r"botocore\.exceptions\.ClientError: An error occurred "
    r"\((?P<code>[^)]+)\) when calling the (?P<operation>\S+) operation: "
    r"(?P<message>.*)"
)
_CREDENTIAL_ERROR_REGEX = re.compile(
    r"\b(?P<code>InvalidClientTokenId|InvalidAccessKeyId|SignatureDoesNotMatch|"
    r"ExpiredToken|AuthFailure|NoCredentialProviders|Unable to locate credentials)\b"
)
_SINGLE_PERMISSIONS_REGEX = re.compile(
    r"^\s*(?P<count>\d+)\s+(?P<state>Confirmed|Unconfirmed)\s+permissions\s+"
    r"for\s+(?P<kind>user|role):\s*(?P<subject>.+?)\.\s*$",
    re.IGNORECASE,
)
_PLURAL_PERMISSIONS_REGEX = re.compile(
    r"^\s*(?P<count>\d+)\s+(?P<state>Confirmed|Unconfirmed)\s+permissions\s+"
    r"for\s+(?P<number>\d+)\s+(?P<kind>user|role)\(s\)\.\s*$",
    re.IGNORECASE,
)
_CONFIRMED_METHOD_REGEX = re.compile(r"CONFIRMED:\s*(\S+)")
_POTENTIAL_METHOD_REGEX = re.compile(r"POTENTIAL:\s*(\S+)")
_BUCKET_NAME_REGEX = re.compile(r'Found bucket "(?P<name>[^"]+)"')
_TOTAL_BUCKETS_REGEX = re.compile(r"(\d+)\s+total buckets found")
_READABLE_BUCKETS_REGEX = re.compile(r"(\d+)\s+buckets found with read permissions")
_DOWNLOADED_FILES_REGEX = re.compile(r"(\d+)\s+files downloaded")
_S3_OBJECT_REGEX = re.compile(r"^(?P<key>.+)@(?P<bucket>[^@]+)$")


@dataclass
class RawPacuEnumResult:
    target: str = ""
    action: str = ""
    session: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None
    # Contents of Pacu's --names-only file, read before the disposable
    # HOME is removed. Empty when the module did not write one.
    names_text: str = ""


def _combined_output(raw: RawPacuEnumResult) -> str:
    return f"{raw.stdout or ''}\n{raw.stderr or ''}"


def _tail(text: str) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _last_exception_line(text: str) -> str:
    """Returns the last non-empty traceback line (the actual exception)."""
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    for line in reversed(lines):
        if line.startswith("Traceback (most recent call last)"):
            break
        if ":" in line or line.endswith("Error"):
            return line[:MAX_ERROR_CHARS]
    return (lines[-1] if lines else "")[:MAX_ERROR_CHARS]


def redact_credentials(text: str, credential: str) -> str:
    """Replaces every credential component echoed in Pacu output with
    ``<redacted>`` before it can reach the model or evidence."""
    if not text:
        return text
    parts = [part.strip() for part in (credential or "").split(":", 2)]
    for secret in sorted({part for part in parts if part}, key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    return text


def extract_error(raw: RawPacuEnumResult) -> Optional[str]:
    """Returns a hard execution error, or None if Pacu produced a result.

    An ``AccessDenied`` inside one enumerated service is not a hard error
    (Pacu records that permission as unconfirmed and keeps going); only a
    credential rejection, an uncaught traceback, or a non-zero exit is.
    """
    if raw.error:
        return raw.error

    text = _combined_output(raw)

    match = _CLIENT_ERROR_REGEX.search(text)
    if match:
        message = match.group("message").strip()
        return (
            f"AWS API error ({match.group('code')}) from "
            f"{match.group('operation')}: {message}"
        )[:MAX_ERROR_CHARS]

    if "EOFError: EOF when reading a line" in text:
        return (
            "pacu required interactive input but was run non-interactively "
            "(stdin closed); a prerequisite module or the supplied credentials "
            "did not provide the data it needed"
        )

    if "Traceback (most recent call last)" in text:
        return _last_exception_line(text)

    credential_match = _CREDENTIAL_ERROR_REGEX.search(text)
    if credential_match:
        return f"AWS credential error: {credential_match.group('code')}"

    if raw.returncode != 0:
        tail = _tail(text)
        return (
            f"pacu exited with code {raw.returncode}"
            + (f": {tail}" if tail else "")
        )[:MAX_ERROR_CHARS]

    return None


def _parse_enum_permissions(text: str) -> Dict[str, Any]:
    counts: Dict[str, int] = {
        "users_confirmed": 0,
        "users_confirmed_permission_count": 0,
        "users_unconfirmed": 0,
        "users_unconfirmed_permission_count": 0,
        "roles_confirmed": 0,
        "roles_confirmed_permission_count": 0,
        "roles_unconfirmed": 0,
        "roles_unconfirmed_permission_count": 0,
    }
    subjects: List[str] = []
    summary: List[str] = []
    recognized = False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        single = _SINGLE_PERMISSIONS_REGEX.match(line)
        if single:
            recognized = True
            state = single.group("state").lower()
            kind = single.group("kind").lower()
            count = int(single.group("count"))
            subject = single.group("subject").strip()
            counts[f"{kind}s_{state}"] += 1
            counts[f"{kind}s_{state}_permission_count"] += count
            if subject and subject not in subjects:
                subjects.append(subject)
            if len(summary) < MAX_SUMMARY_LINES_RETURNED:
                summary.append(stripped)
            continue

        plural = _PLURAL_PERMISSIONS_REGEX.match(line)
        if plural:
            recognized = True
            state = plural.group("state").lower()
            kind = plural.group("kind").lower()
            number = int(plural.group("number"))
            count = int(plural.group("count"))
            counts[f"{kind}s_{state}"] += number
            counts[f"{kind}s_{state}_permission_count"] += count
            if len(summary) < MAX_SUMMARY_LINES_RETURNED:
                summary.append(stripped)

    if not recognized:
        if "Unable to find users/roles to enumerate permissions" in text:
            return {
                "status": "success",
                "notes": [
                    "pacu found no users/roles to enumerate; the supplied "
                    "credential may be a role the module could not resolve."
                ],
            }
        return {
            "status": "failed",
            "error": "pacu produced no recognized iam__enum_permissions summary",
        }

    return {
        "status": "success",
        **counts,
        "subjects": subjects,
        "summary": summary,
    }


def _parse_privesc_scan(text: str) -> Dict[str, Any]:
    confirmed = sorted(set(_CONFIRMED_METHOD_REGEX.findall(text)))
    potential = sorted(set(_POTENTIAL_METHOD_REGEX.findall(text)))
    scan_complete = "Scan Complete" in text
    none_found = bool(re.search(r"^\s*None found\s*$", text, re.MULTILINE))
    already_admin = "already has administrator permissions" in text.lower()

    if not (confirmed or potential or scan_complete or none_found or already_admin):
        return {
            "status": "failed",
            "error": "pacu produced no recognized iam__privesc_scan summary",
        }

    result: Dict[str, Any] = {
        "status": "success",
        "confirmed_methods": confirmed,
        "potential_methods": potential,
        "scan_complete": scan_complete,
        "already_admin": already_admin,
    }
    if not confirmed and not potential and not already_admin:
        result["notes"] = [
            "pacu found no privilege-escalation path for this credential."
        ]
    return result


def _parse_s3_list(text: str, names_text: str) -> Dict[str, Any]:
    total_match = _TOTAL_BUCKETS_REGEX.search(text)
    readable_match = _READABLE_BUCKETS_REGEX.search(text)

    if not total_match and not readable_match:
        if "FAILURE: MISSING AWS PERMISSIONS" in text:
            return {
                "status": "failed",
                "error": "AWS permissions denied: the credential cannot list S3 buckets",
            }
        return {
            "status": "failed",
            "error": "pacu produced no recognized s3__download_bucket summary",
        }

    bucket_names = sorted(set(_BUCKET_NAME_REGEX.findall(text)))
    objects: List[str] = [
        line.strip() for line in (names_text or "").splitlines() if line.strip()
    ]

    result: Dict[str, Any] = {
        "status": "success",
        "buckets": int(total_match.group(1)) if total_match else len(bucket_names),
        "readable_buckets": (
            int(readable_match.group(1)) if readable_match else 0
        ),
        "bucket_names": bucket_names[:MAX_BUCKET_NAMES_RETURNED],
        "bucket_names_truncated": (
            len(bucket_names) > MAX_BUCKET_NAMES_RETURNED
        ),
        "objects_listed": len(objects),
        "objects_sample": objects[:MAX_OBJECTS_RETURNED],
        "objects_truncated": len(objects) > MAX_OBJECTS_RETURNED,
    }

    if result["readable_buckets"] and not objects:
        result["notes"] = [
            "pacu reported readable buckets but wrote no object-name file; "
            "rerun the enum action or inspect the evidence transcript."
        ]
    return result


def parse_pacu_enum_result(raw: RawPacuEnumResult) -> Dict[str, Any]:
    """Turns one raw pacu_enum invocation into the model-facing result."""
    base: Dict[str, Any] = {
        "target": raw.target,
        "action": raw.action,
        "mode": "enum",
    }

    error = extract_error(raw)
    if error:
        return {**base, "status": "failed", "error": error}

    text = _combined_output(raw)

    if raw.action == "enum_permissions":
        parsed = _parse_enum_permissions(text)
    elif raw.action == "privesc_scan":
        parsed = _parse_privesc_scan(text)
    elif raw.action == "s3_list":
        parsed = _parse_s3_list(text, raw.names_text)
    else:
        return {
            **base,
            "status": "failed",
            "error": f"unsupported pacu_enum action '{raw.action}'",
        }

    return {**base, **parsed}


def parse_s3_object_entry(entry: str) -> Optional[Dict[str, str]]:
    """Splits a ``key@bucket`` line from Pacu's names-only file."""
    match = _S3_OBJECT_REGEX.match((entry or "").strip())
    if not match:
        return None
    return {"key": match.group("key"), "bucket": match.group("bucket")}


def cap_evidence(text: str) -> str:
    """Bounds the transcript stored as evidence to MAX_EVIDENCE_CHARS."""
    if len(text) <= MAX_EVIDENCE_CHARS:
        return text
    return text[:MAX_EVIDENCE_CHARS]
