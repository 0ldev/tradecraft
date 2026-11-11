"""
Subprocess execution for kubectl: runs auth can-i and get secrets.
No parsing logic here -- see parse.py.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional

from tradecraft.adapters.kubectl import parse as k8s_parse

DEFAULT_TIMEOUT = 30


def find_kubectl_binary() -> Optional[str]:
    """Finds kubectl binary on PATH."""
    return shutil.which("kubectl")


def build_can_i_argv(
    server_endpoint: str,
    token: str,
    namespace: Optional[str] = None,
    binary: str = "kubectl",
) -> List[str]:
    """Builds argv for `kubectl auth can-i --list`."""
    argv = [
        binary,
        f"--server=https://{server_endpoint}",
        f"--token={token}",
        "--insecure-skip-tls-verify",
        "auth",
        "can-i",
        "--list",
    ]
    if namespace:
        argv.extend(["-n", namespace])
    return argv


def build_get_secrets_argv(
    server_endpoint: str,
    token: str,
    namespace: Optional[str] = None,
    binary: str = "kubectl",
) -> List[str]:
    """Builds argv for `kubectl get secrets -o json`."""
    argv = [
        binary,
        f"--server=https://{server_endpoint}",
        f"--token={token}",
        "--insecure-skip-tls-verify",
        "get",
        "secrets",
    ]
    if namespace:
        argv.extend(["-n", namespace])
    else:
        argv.append("--all-namespaces")
    argv.extend(["-o", "json"])
    return argv


def execute(
    target: str,
    token: str,
    namespace: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    runner=None,
) -> k8s_parse.RawKubectlResult:
    """Executes kubectl inspection across API server permissions and secrets."""
    endpoint = k8s_parse.parse_target_endpoint(target)
    if not endpoint:
        return k8s_parse.RawKubectlResult(error="empty target API server endpoint")
    if not token or not token.strip():
        return k8s_parse.RawKubectlResult(target=endpoint, error="missing required token parameter")

    binary = find_kubectl_binary()
    if binary is None:
        return k8s_parse.RawKubectlResult(
            target=endpoint, error="kubectl binary not found on PATH"
        )

    run_cmd = runner or subprocess.run
    effective_ns = namespace.strip() if namespace and namespace.strip() else k8s_parse.namespace_from_token(token)

    result = k8s_parse.RawKubectlResult(
        target=endpoint,
        namespace=effective_ns,
    )

    can_i_argv = build_can_i_argv(endpoint, token.strip(), namespace=effective_ns, binary=binary)
    try:
        proc = run_cmd(
            can_i_argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        result.error = "kubectl auth can-i timed out"
        return result
    except Exception as e:
        result.error = f"kubectl auth can-i failed: {e}"
        return result

    if proc.returncode != 0:
        result.error = f"kubectl auth can-i failed (exit {proc.returncode}): {proc.stderr.strip()}"
        return result

    overprivileged, can_get_secrets, permissions = k8s_parse.parse_can_i_output(proc.stdout)
    result.overprivileged = overprivileged
    result.permissions = permissions

    # 2. Step 2: get secrets if permissions allow
    if can_get_secrets:
        # Try cluster-wide first, then namespace-specific if cluster-wide fails
        attempts = []
        if not namespace:
            attempts.append((build_get_secrets_argv(endpoint, token.strip(), namespace=None, binary=binary), None))
        if effective_ns:
            attempts.append((build_get_secrets_argv(endpoint, token.strip(), namespace=effective_ns, binary=binary), effective_ns))

        secrets_stdout = ""
        for sec_argv, _ in attempts:
            try:
                sec_proc = run_cmd(
                    sec_argv,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                if sec_proc.returncode == 0:
                    secrets_stdout = sec_proc.stdout
                    break
            except Exception:
                continue

        if secrets_stdout:
            result.secrets = k8s_parse.parse_secrets_output(secrets_stdout)

    return result
