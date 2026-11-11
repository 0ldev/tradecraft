"""
Subprocess execution for scoutsuite_audit: drives the real `scout` CLI
(ScoutSuite) non-interactively, read-only, once per call.

Each call runs inside a disposable HOME and a disposable report directory
(both under one TemporaryDirectory), so ScoutSuite's own config/cache and
the raw report never persist past one invocation. The raw service-account
JSON for GCP is written to a 0600 file inside that same directory and
removed with it.

Auth shapes (mirroring pacu_enum's colon-joined convention for AWS/Azure):
  aws   -- "AccessKeyId:SecretAccessKey[:SessionToken]"
           -> scout aws --access-keys --access-key-id ... --secret-access-key ...
              [--session-token ...]
  azure -- "TenantId:ClientId:ClientSecret[:SubscriptionId]"
           -> scout azure --service-principal --tenant ... --client-id ...
              --client-secret ... [--subscriptions ...]
  gcp   -- raw or base64-encoded service-account JSON (never a file path
           from the model; a colon-split would corrupt the JSON)
           -> scout gcp --service-account <tmpfile>

Every credential shape check happens before any subprocess runs, and bad
input returns a RawScoutSuiteResult with `error` set rather than raising.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from tradecraft.adapters.scoutsuite_audit.parse import RawScoutSuiteResult

SCOUT_BIN = "scout"  # confirmed: scout 5.14.0 on CT 115 (/usr/local/bin/scout)
TIMEOUT_SECONDS = 600
MAX_WORKERS = 10
PROVIDERS = ("aws", "azure", "gcp")
_SERVICES_REGEX = re.compile(r"^[A-Za-z0-9_-]+(,[A-Za-z0-9_-]+)*$")
_REPORT_GLOB = "scoutsuite_results_*.js"


def is_available() -> bool:
    return shutil.which(SCOUT_BIN) is not None


def _redact(text: str, secrets: List[str]) -> str:
    if not text:
        return text
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    return text


def _split_colon(credential: str, min_parts: int, max_parts: int) -> Optional[List[str]]:
    parts = [part.strip() for part in (credential or "").split(":")]
    if not (min_parts <= len(parts) <= max_parts):
        return None
    if any(not part for part in parts[:min_parts]):
        return None
    return parts


def _aws_args(credential: str) -> Optional[List[str]]:
    parts = _split_colon(credential, 2, 3)
    if parts is None:
        return None
    args = [
        "aws",
        "--access-keys",
        "--access-key-id", parts[0],
        "--secret-access-key", parts[1],
    ]
    if len(parts) == 3 and parts[2]:
        args += ["--session-token", parts[2]]
    return args


def _azure_args(credential: str) -> Optional[List[str]]:
    parts = _split_colon(credential, 3, 4)
    if parts is None:
        return None
    args = [
        "azure",
        "--service-principal",
        "--tenant", parts[0],
        "--client-id", parts[1],
        "--client-secret", parts[2],
    ]
    if len(parts) == 4 and parts[3]:
        args += ["--subscriptions", parts[3]]
    return args


def _decode_service_account(credential: str) -> Optional[Dict[str, Any]]:
    """Accepts raw or base64-encoded service-account JSON.

    Order is fixed: try base64 first (validate=True so a raw JSON string
    cannot silently decode as base64), then fall back to the raw string.
    Either way the result must be a JSON object with
    "type": "service_account".
    """
    parsed: Any = None
    try:
        decoded = base64.b64decode(credential, validate=True)
        parsed = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        parsed = None

    if parsed is None:
        try:
            parsed = json.loads(credential)
        except (ValueError, TypeError):
            return None

    if not isinstance(parsed, dict):
        return None
    if parsed.get("type") != "service_account":
        return None
    return parsed


def _write_service_account(directory: str, payload: Dict[str, Any]) -> str:
    path = os.path.join(directory, "service_account.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(payload, handle)
    os.chmod(path, 0o600)
    return path


def _report_file(report_dir: str) -> Optional[Path]:
    matches = sorted(Path(report_dir).rglob(_REPORT_GLOB))
    return matches[0] if matches else None


def execute(
    target: str,
    provider: str,
    credential: str,
    services: Optional[str] = None,
) -> RawScoutSuiteResult:
    """Runs one read-only ScoutSuite audit of `provider` using `credential`.

    `target` is only an identifying label (echoed back, never passed to
    scout). `services` is an optional comma-separated service list passed
    to `--services`.
    """
    provider = (provider or "").strip().lower()
    if provider not in PROVIDERS:
        return RawScoutSuiteResult(
            target=target, provider=provider,
            error=f"provider must be one of: {', '.join(PROVIDERS)}",
        )

    services_value = (services or "").strip() or None
    if services_value is not None and not _SERVICES_REGEX.match(services_value):
        return RawScoutSuiteResult(
            target=target, provider=provider,
            error="services must be a comma-separated list of service names "
                  "(letters, digits, '_' and '-' only)",
        )

    credential = credential or ""
    secrets: List[str] = []

    with tempfile.TemporaryDirectory(prefix="scoutsuite_audit_") as workdir:
        home = os.path.join(workdir, "home")
        report_dir = os.path.join(workdir, "report")
        os.makedirs(home)

        if provider == "aws":
            provider_args = _aws_args(credential)
            if provider_args is None:
                return RawScoutSuiteResult(
                    target=target, provider=provider,
                    error="credential must be 'AccessKeyId:SecretAccessKey[:SessionToken]'",
                )
            secrets = [part.strip() for part in credential.split(":")]
        elif provider == "azure":
            provider_args = _azure_args(credential)
            if provider_args is None:
                return RawScoutSuiteResult(
                    target=target, provider=provider,
                    error="credential must be "
                          "'TenantId:ClientId:ClientSecret[:SubscriptionId]'",
                )
            secrets = [part.strip() for part in credential.split(":")]
        else:
            payload = _decode_service_account(credential)
            if payload is None:
                return RawScoutSuiteResult(
                    target=target, provider=provider,
                    error="credential must be raw or base64-encoded "
                          "service-account JSON with \"type\": \"service_account\"",
                )
            secrets = [str(payload.get("private_key", "")),
                       str(payload.get("private_key_id", ""))]
            key_path = _write_service_account(workdir, payload)
            provider_args = ["gcp", "--service-account", key_path]

        argv = [SCOUT_BIN] + provider_args + [
            "--report-dir", report_dir,
            "--no-browser",
            "--max-workers", str(MAX_WORKERS),
        ]
        if services_value:
            # scout's --services is nargs='+': each service is its own argv token.
            argv += ["--services"] + services_value.split(",")

        env = dict(os.environ)
        env["HOME"] = home

        try:
            proc = subprocess.run(
                argv,
                text=True,
                capture_output=True,
                timeout=TIMEOUT_SECONDS,
                stdin=subprocess.DEVNULL,
                env=env,
                cwd=home,
            )
        except FileNotFoundError:
            return RawScoutSuiteResult(
                target=target, provider=provider,
                error="scout executable not found on PATH",
            )
        except subprocess.TimeoutExpired:
            return RawScoutSuiteResult(
                target=target, provider=provider,
                error=f"scout timed out after {TIMEOUT_SECONDS}s",
            )

        report_text = ""
        report_path = _report_file(report_dir)
        if report_path is not None:
            report_text = report_path.read_text(errors="ignore")

        return RawScoutSuiteResult(
            target=target,
            provider=provider,
            stdout=_redact(proc.stdout or "", secrets),
            stderr=_redact(proc.stderr or "", secrets),
            returncode=proc.returncode,
            report_text=report_text,
        )
