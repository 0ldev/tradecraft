"""
Subprocess execution for trivy_k8s_scan: drives the real `trivy k8s` CLI
(Aqua Trivy's live-cluster mode) once per call, against a kubeconfig file
already on the scanning host.

Reports known CVEs in running workload images and Kubernetes
misconfigurations (RBAC, pod security, exposed secrets) across the cluster
or one namespace. The scan is read-only: no `--fix`, no write flag, and
`--disable-node-collector` is always passed -- by default `trivy k8s`
collects node configuration by deploying a short-lived Job/Pod and a
dedicated namespace into the cluster, which would be a cluster write this
tool's `destructive: false` contract does not account for. Node-level
findings are the tradeoff for staying genuinely read-only; add a separate
destructive variant later if node collection is ever needed. Each call
writes its JSON report into a disposable TemporaryDirectory, read back and
removed with it.

Design notes (judgment calls, see the tool contract for the model-facing
side):
  * kubeconfig is a PATH to a file on the local filesystem, not inline YAML.
    Writing inline kubeconfig to a temp file would put cluster credentials
    into a second on-disk copy the operator did not ask for; a path lets the
    operator keep one copy under their own control.
  * `--report all` rather than `--report summary`: the JSON layout of the
    summary report is not documented by Trivy, while the `all` layout
    (per-resource Vulnerabilities / Misconfigurations arrays) is.
  * Context is a positional argument (`trivy k8s [flags] [CONTEXT]`), not a
    flag, and is placed last. It is validated so it can never be read as a
    flag.
  * Namespace scoping uses `--include-namespaces`. The namespace is validated
    as a DNS label before it reaches argv.
  * Trivy's own `--timeout` (540s) sits below the subprocess cap (600s) so
    trivy stops itself cleanly before the process is killed.

Every input check happens before any subprocess runs, and bad input or a
genuine execution failure returns a RawTrivyK8sResult with `error` set
rather than raising.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional

from tradecraft.adapters.trivy_k8s_scan.parse import RawTrivyK8sResult

TRIVY_BIN = "trivy"
TIMEOUT_SECONDS = 600
TRIVY_INTERNAL_TIMEOUT = "540s"
MAX_PATH_CHARS = 1024
MAX_CONTEXT_CHARS = 253
# Namespace: a DNS label (RFC 1123), max 63 chars.
_NAMESPACE_REGEX = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
# Kubeconfig context names are free-form, but must never start with '-' so
# they cannot be read as a trivy flag.
_CONTEXT_REGEX = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._:/@+-]*$")
_REPORT_NAME = "trivy_k8s_report.json"


def is_available() -> bool:
    return shutil.which(TRIVY_BIN) is not None


def execute(
    kubeconfig: str,
    namespace: str = "",
    context: str = "",
) -> RawTrivyK8sResult:
    """Runs one read-only trivy k8s scan using the kubeconfig at `kubeconfig`.

    `namespace` (optional) restricts the scan to one namespace; empty scans
    the whole cluster. `context` (optional) selects a kubeconfig context when
    the file holds more than one.
    """
    kubeconfig = (kubeconfig or "").strip()
    if (
        not kubeconfig
        or len(kubeconfig) > MAX_PATH_CHARS
        or kubeconfig.startswith("-")
        or "\x00" in kubeconfig
    ):
        return RawTrivyK8sResult(
            kubeconfig=kubeconfig,
            error="kubeconfig must be a path to a kubeconfig file (must not start with '-')",
        )
    if not os.path.isfile(kubeconfig):
        return RawTrivyK8sResult(
            kubeconfig=kubeconfig,
            error=f"kubeconfig file not found: {kubeconfig}",
        )

    namespace = (namespace or "").strip()
    if namespace and not _NAMESPACE_REGEX.match(namespace):
        return RawTrivyK8sResult(
            kubeconfig=kubeconfig,
            error="namespace must be a valid Kubernetes namespace name (lowercase letters, digits, '-')",
        )

    context = (context or "").strip()
    if context and (len(context) > MAX_CONTEXT_CHARS or not _CONTEXT_REGEX.match(context)):
        return RawTrivyK8sResult(
            kubeconfig=kubeconfig,
            error="context must be a kubeconfig context name (letters, digits, and . _ : / @ + - only)",
        )

    with tempfile.TemporaryDirectory(prefix="trivy_k8s_scan_") as workdir:
        report_path = os.path.join(workdir, _REPORT_NAME)
        argv = [
            TRIVY_BIN, "k8s",
            "--kubeconfig", kubeconfig,
            "--disable-node-collector",
            "--report", "all",
            "--format", "json",
            "--output", report_path,
            "--no-progress",
            "--timeout", TRIVY_INTERNAL_TIMEOUT,
        ]
        if namespace:
            argv += ["--include-namespaces", namespace]
        if context:
            argv.append(context)

        try:
            proc = subprocess.run(
                argv,
                text=True,
                capture_output=True,
                timeout=TIMEOUT_SECONDS,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return RawTrivyK8sResult(kubeconfig=kubeconfig, error="trivy executable not found on PATH")
        except subprocess.TimeoutExpired:
            return RawTrivyK8sResult(
                kubeconfig=kubeconfig,
                error=f"trivy k8s timed out after {TIMEOUT_SECONDS}s",
            )

        report_text = ""
        if os.path.isfile(report_path):
            with open(report_path, errors="ignore") as handle:
                report_text = handle.read()

        return RawTrivyK8sResult(
            kubeconfig=kubeconfig,
            namespace=namespace,
            context=context,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            report_text=report_text,
        )
