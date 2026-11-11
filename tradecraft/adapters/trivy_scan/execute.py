"""
Subprocess execution for trivy_scan: drives the real `trivy image` CLI
(Aqua Trivy) non-interactively, read-only, once per call.

The scan reads a container image's packages and reports known
vulnerabilities; it never pushes, pulls into a daemon, or mutates the image
or the registry. Each call writes its JSON report into a disposable
TemporaryDirectory, read back and removed with it.

Design notes (judgment calls, see the tool contract for the model-facing
side):
  * `--image-src remote` -- scan the registry reference itself, never a
    same-named image that happens to sit in a local Docker/containerd/Podman
    store on the scanning host.
  * `--scanners vuln` -- vulnerability detection only; trivy's default also
    runs secret scanning, which this tool does not request.
  * `--list-all-pkgs=false` -- trivy's default inlines every installed
    package into the JSON whether or not it is vulnerable; only vulnerable
    entries are needed here.
  * Registry credential, when given, is `username:password` split on the
    FIRST colon (passwords may contain colons). It is passed through the
    TRIVY_USERNAME / TRIVY_PASSWORD env vars, not argv, so it never shows up
    in the process table. Any pre-existing TRIVY_USERNAME/TRIVY_PASSWORD in
    the parent env is cleared first so an unauthenticated call cannot pick
    up a stray operator credential.
  * The trivy vulnerability DB lives in trivy's default cache dir
    (~/.cache/trivy) and is deliberately NOT disposable: re-downloading it
    on every call would cost ~50s per call. The DB is vendor data, not
    target state.
  * Trivy's own `--timeout` (540s) sits below the subprocess cap (600s) so
    trivy stops itself cleanly before the process is killed.

Every input check happens before any subprocess runs, and bad input or a
genuine execution failure returns a RawTrivyResult with `error` set rather
than raising.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Optional

from tradecraft.adapters.trivy_scan.parse import RawTrivyResult

TRIVY_BIN = "trivy"  # confirmed: trivy 0.71.2 on CT 115 (/usr/bin/trivy, Aqua apt repo)
TIMEOUT_SECONDS = 600
TRIVY_INTERNAL_TIMEOUT = "540s"
MAX_TARGET_CHARS = 255
# Image references: [registry[:port]/]repo[:tag][@sha256:digest]. Must start
# alphanumeric so a value can never be read as a trivy flag.
_IMAGE_REF_REGEX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
_REPORT_NAME = "trivy_report.json"


def is_available() -> bool:
    return shutil.which(TRIVY_BIN) is not None


def _redact(text: str, secrets: List[str]) -> str:
    if not text:
        return text
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    return text


def _split_credential(credential: str) -> Optional[tuple]:
    username, sep, password = credential.partition(":")
    if not sep or not username or not password:
        return None
    return username, password


def execute(target: str, credential: str = "") -> RawTrivyResult:
    """Runs one read-only trivy vulnerability scan of the image `target`.

    `credential` is optional `username:password` for a private registry.
    Public images need none.
    """
    target = (target or "").strip()
    if not target or len(target) > MAX_TARGET_CHARS or not _IMAGE_REF_REGEX.match(target):
        return RawTrivyResult(
            target=target,
            error="target must be a container image reference such as "
                  "'nginx:1.25' or 'registry.example.com/app@sha256:...' "
                  "(letters, digits, and . _ : / @ + - only)",
        )

    credential = credential or ""
    creds = None
    secrets: List[str] = []
    if credential.strip():
        creds = _split_credential(credential.strip())
        if creds is None:
            return RawTrivyResult(
                target=target,
                error="credential must be 'username:password' (both non-empty)",
            )
        secrets = [creds[0], creds[1]]

    with tempfile.TemporaryDirectory(prefix="trivy_scan_") as workdir:
        report_path = os.path.join(workdir, _REPORT_NAME)
        argv = [
            TRIVY_BIN, "image",
            "--format", "json",
            "--output", report_path,
            "--scanners", "vuln",
            "--image-src", "remote",
            "--list-all-pkgs=false",
            "--no-progress",
            "--skip-version-check",
            "--timeout", TRIVY_INTERNAL_TIMEOUT,
            target,
        ]

        env = dict(os.environ)
        env.pop("TRIVY_USERNAME", None)
        env.pop("TRIVY_PASSWORD", None)
        if creds is not None:
            env["TRIVY_USERNAME"] = creds[0]
            env["TRIVY_PASSWORD"] = creds[1]

        try:
            proc = subprocess.run(
                argv,
                text=True,
                capture_output=True,
                timeout=TIMEOUT_SECONDS,
                stdin=subprocess.DEVNULL,
                env=env,
            )
        except FileNotFoundError:
            return RawTrivyResult(target=target, error="trivy executable not found on PATH")
        except subprocess.TimeoutExpired:
            return RawTrivyResult(
                target=target,
                error=f"trivy timed out after {TIMEOUT_SECONDS}s",
            )

        report_text = ""
        if os.path.isfile(report_path):
            with open(report_path, errors="ignore") as handle:
                report_text = handle.read()

        return RawTrivyResult(
            target=target,
            stdout=_redact(proc.stdout or "", secrets),
            stderr=_redact(proc.stderr or "", secrets),
            returncode=proc.returncode,
            report_text=report_text,
        )
