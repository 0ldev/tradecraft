"""
Unit tests for the pod_exec_enum adapter and tool layer. The kubectl
subprocess call is mocked. The sample stdout fixtures below were captured
by running the fixed in-container script locally with `sh`: the absent
fixture is the literal output on a host with no service-account mount, and
the present fixture is the same script with its paths pointed at scratch
files (token, namespace, Docker socket) -- the CapEff line is the real
value from /proc/self/status.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from tradecraft.adapters.pod_exec_enum import execute as pee_execute
from tradecraft.adapters.pod_exec_enum import parse as pee_parse
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.pod_exec_enum import PodExecEnum

ABSENT_OUTPUT = """\
@@PEE:BEGIN sa_token
token_file absent
namespace_file absent
@@PEE:END sa_token
@@PEE:BEGIN docker_socket
socket absent
@@PEE:END docker_socket
@@PEE:BEGIN capabilities
capeff 0000000000000000
@@PEE:END capabilities
@@PEE:BEGIN cgroup_release_agent
cgroup_version v2
@@PEE:END cgroup_release_agent
@@PEE:DONE
"""

PRESENT_OUTPUT = """\
@@PEE:BEGIN sa_token
token_file present
token_size_bytes 92
@@PEE:TOKEN_BEGIN
eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDp3ZWIifQ.c2lnbmF0dXJl
@@PEE:TOKEN_END
namespace_file present
namespace_value default
@@PEE:END sa_token
@@PEE:BEGIN docker_socket
socket present
writable yes
@@PEE:END docker_socket
@@PEE:BEGIN capabilities
capeff 00000000a80425fb
@@PEE:END capabilities
@@PEE:BEGIN cgroup_release_agent
cgroup_version v1
memory_release_agent writable
pids_release_agent not_writable
@@PEE:END cgroup_release_agent
@@PEE:DONE
"""

SERVER = "10.0.0.1:6443"
TOKEN = "eyJhbGciOiJSUzI1NiJ9.fake-bearer-token"


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _fake_runner(proc):
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return proc

    runner.calls = calls
    return runner


def _no_call_runner(argv, **kwargs):
    raise AssertionError("kubectl must not run when validation fails")


# ---------------------------------------------------------------------------
# build_argv / script
# ---------------------------------------------------------------------------


def test_build_argv_single_container_no_c_flag():
    argv = pee_execute.build_argv(
        endpoint=SERVER, token=TOKEN, namespace="default", pod="web-abc", binary="/usr/bin/kubectl"
    )
    assert argv[:5] == ["/usr/bin/kubectl", "exec", "web-abc", "-n", "default"]
    assert "-c" not in argv[: argv.index("--")]
    assert argv[5:9] == [
        "--server=https://10.0.0.1:6443",
        f"--token={TOKEN}",
        "--insecure-skip-tls-verify",
        "--",
    ]
    assert argv[9:11] == ["sh", "-c"]
    assert argv[11] == pee_execute.REMOTE_SCRIPT


def test_build_argv_with_container_adds_c_flag():
    argv = pee_execute.build_argv(
        endpoint=SERVER, token=TOKEN, namespace="prod", pod="web-abc", container="app"
    )
    assert argv[:7] == ["kubectl", "exec", "web-abc", "-n", "prod", "-c", "app"]
    assert argv[-1] == pee_execute.REMOTE_SCRIPT


def test_script_is_fixed_and_contains_no_model_input():
    argv = pee_execute.build_argv(
        endpoint="evil.example:6443",
        token="TOKENSENTINEL123",
        namespace="nsmarker",
        pod="podmarker",
        container="ctrmarker",
    )
    script = argv[-1]
    for sentinel in ("evil.example", "TOKENSENTINEL123", "nsmarker", "podmarker", "ctrmarker"):
        assert sentinel not in script


def test_script_checks_all_four_indicators_read_only():
    script = pee_execute.REMOTE_SCRIPT
    assert "/var/run/secrets/kubernetes.io/serviceaccount" in script
    assert "/var/run/docker.sock" in script
    assert "[ -w " in script
    assert "/proc/self/status" in script
    assert pee_execute.CGROUP_V2_MARKER in script
    for ctrl in pee_execute.CGROUP_CONTROLLERS:
        assert f"/sys/fs/cgroup/{ctrl}/release_agent" in script
    for mutating in ("rm ", "mv ", "chmod", "chown", "tee ", ">>", "> "):
        # the only redirections in the script are `< file` and `2>/dev/null`
        assert mutating not in script


# ---------------------------------------------------------------------------
# execute() validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs,fragment",
    [
        ({"server": "", "token": TOKEN, "namespace": "default", "pod": "web"}, "empty server"),
        ({"server": SERVER, "token": "  ", "namespace": "default", "pod": "web"}, "missing required token"),
        ({"server": SERVER, "token": TOKEN, "namespace": "-n", "pod": "web"}, "invalid namespace"),
        ({"server": SERVER, "token": TOKEN, "namespace": "Default", "pod": "web"}, "invalid namespace"),
        ({"server": SERVER, "token": TOKEN, "namespace": "default", "pod": "--rm"}, "invalid pod"),
        ({"server": SERVER, "token": TOKEN, "namespace": "default", "pod": ""}, "invalid pod"),
        (
            {"server": SERVER, "token": TOKEN, "namespace": "default", "pod": "web", "container": "-x"},
            "invalid container",
        ),
    ],
)
def test_execute_rejects_invalid_inputs_without_running_kubectl(kwargs, fragment):
    with patch("tradecraft.adapters.pod_exec_enum.execute.find_kubectl_binary", return_value="/usr/bin/kubectl"):
        raw = pee_execute.execute(runner=_no_call_runner, **kwargs)
    assert raw.error is not None and fragment in raw.error


def test_execute_missing_binary_reports_error():
    with patch("tradecraft.adapters.pod_exec_enum.execute.find_kubectl_binary", return_value=None):
        raw = pee_execute.execute(
            server=SERVER, token=TOKEN, namespace="default", pod="web", runner=_no_call_runner
        )
    assert raw.error == "kubectl binary not found on PATH"


def test_execute_success_passes_fixed_argv_and_bounded_timeout():
    runner = _fake_runner(_completed(stdout=ABSENT_OUTPUT))
    with patch("tradecraft.adapters.pod_exec_enum.execute.find_kubectl_binary", return_value="/usr/bin/kubectl"):
        raw = pee_execute.execute(
            server="https://" + SERVER + "/",
            token=TOKEN,
            namespace="default",
            pod="web-abc",
            container="app",
            runner=runner,
        )
    assert raw.error is None
    assert raw.stdout == ABSENT_OUTPUT
    assert raw.returncode == 0
    assert raw.server == SERVER
    assert raw.container == "app"
    (argv, kwargs), = runner.calls
    assert argv[0] == "/usr/bin/kubectl"
    assert "--server=https://10.0.0.1:6443" in argv
    assert kwargs["timeout"] == pee_execute.DEFAULT_TIMEOUT
    assert kwargs["stdin"] == subprocess.DEVNULL


def test_execute_timeout_reported_as_error():
    def runner(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=60)

    with patch("tradecraft.adapters.pod_exec_enum.execute.find_kubectl_binary", return_value="/usr/bin/kubectl"):
        raw = pee_execute.execute(server=SERVER, token=TOKEN, namespace="default", pod="web", runner=runner)
    assert "timed out" in raw.error


def test_execute_unexpected_exception_reported_as_error():
    def runner(argv, **kwargs):
        raise OSError("boom")

    with patch("tradecraft.adapters.pod_exec_enum.execute.find_kubectl_binary", return_value="/usr/bin/kubectl"):
        raw = pee_execute.execute(server=SERVER, token=TOKEN, namespace="default", pod="web", runner=runner)
    assert raw.error == "kubectl exec failed: boom"


# ---------------------------------------------------------------------------
# decode_capability_mask
# ---------------------------------------------------------------------------


def test_decode_zero_mask_has_no_capabilities():
    out = pee_parse.decode_capability_mask("0000000000000000")
    assert out["effective_capabilities"] == []
    assert out["unknown_bits"] == []


@pytest.mark.parametrize(
    "mask,expected",
    [
        ("0000000000200000", "CAP_SYS_ADMIN"),   # bit 21
        ("0000000000080000", "CAP_SYS_PTRACE"),  # bit 19
        ("0000000000001000", "CAP_NET_ADMIN"),   # bit 12
        ("0000000000000002", "CAP_DAC_OVERRIDE"),  # bit 1
        ("0000000000000080", "CAP_SETUID"),      # bit 7
        ("0000000010000000", "CAP_LEASE"),       # bit 28
        ("0000000000010000", "CAP_SYS_MODULE"),  # bit 16
    ],
)
def test_decode_well_known_single_bits(mask, expected):
    names = pee_parse.decode_capability_mask(mask)["effective_capabilities"]
    assert names == [expected]


def test_decode_docker_default_capability_set():
    # Docker's default container set: 14 capabilities (CHOWN, DAC_OVERRIDE,
    # FOWNER, FSETID, KILL, SETGID, SETUID, SETPCAP, NET_BIND_SERVICE,
    # NET_RAW, SYS_CHROOT, MKNOD, AUDIT_WRITE, SETFCAP). Notably absent:
    # SYS_ADMIN, SYS_PTRACE, NET_ADMIN, DAC_READ_SEARCH.
    names = pee_parse.decode_capability_mask("00000000a80425fb")["effective_capabilities"]
    assert names == [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_RAW",
        "CAP_SYS_CHROOT",
        "CAP_MKNOD",
        "CAP_AUDIT_WRITE",
        "CAP_SETFCAP",
    ]
    assert "CAP_SYS_ADMIN" not in names


def test_decode_full_root_set_is_all_41_known_capabilities():
    # 000001ffffffffff is the real CapBnd mask on this kernel: bits 0-40.
    out = pee_parse.decode_capability_mask("000001ffffffffff")
    assert len(out["effective_capabilities"]) == 41
    assert out["effective_capabilities"][0] == "CAP_CHOWN"
    assert out["effective_capabilities"][-1] == "CAP_CHECKPOINT_RESTORE"
    assert out["unknown_bits"] == []


def test_decode_unknown_high_bit_reported_by_number():
    # bit 45 is above CAP_CHECKPOINT_RESTORE (40); reported, not dropped.
    out = pee_parse.decode_capability_mask("0000200000000000")
    assert out["effective_capabilities"] == []
    assert out["unknown_bits"] == [45]


def test_decode_accepts_uppercase_hex():
    names = pee_parse.decode_capability_mask("0000000000200000")["effective_capabilities"]
    assert names == ["CAP_SYS_ADMIN"]


def test_decode_rejects_non_hex():
    with pytest.raises(ValueError):
        pee_parse.decode_capability_mask("zz")


def test_capability_table_matches_kernel_last_cap():
    assert len(pee_parse.CAPABILITY_NAMES) == 41
    assert pee_parse.CAPABILITY_NAMES[21] == "CAP_SYS_ADMIN"
    assert pee_parse.CAPABILITY_NAMES[40] == "CAP_CHECKPOINT_RESTORE"


# ---------------------------------------------------------------------------
# cgroup_release_agent
# ---------------------------------------------------------------------------


def test_cgroup_v2_reports_version_only_no_controllers():
    out = (
        "@@PEE:BEGIN cgroup_release_agent\n"
        "cgroup_version v2\n"
        "@@PEE:END cgroup_release_agent\n"
        "@@PEE:DONE\n"
    )
    checks, _ = pee_parse.parse_pod_exec_output(out)
    assert checks["cgroup_release_agent"] == {"cgroup_version": "v2"}


def test_cgroup_v1_all_controllers_not_writable():
    out = (
        "@@PEE:BEGIN cgroup_release_agent\n"
        "cgroup_version v1\n"
        "memory_release_agent not_writable\n"
        "pids_release_agent not_writable\n"
        "@@PEE:END cgroup_release_agent\n"
        "@@PEE:DONE\n"
    )
    checks, _ = pee_parse.parse_pod_exec_output(out)
    cgroup = checks["cgroup_release_agent"]
    assert cgroup["release_agent_writable"] is False
    assert cgroup["controllers"] == {"memory": "not_writable", "pids": "not_writable"}


def test_cgroup_v1_controller_absent():
    out = (
        "@@PEE:BEGIN cgroup_release_agent\n"
        "cgroup_version v1\n"
        "memory_release_agent absent\n"
        "pids_release_agent absent\n"
        "@@PEE:END cgroup_release_agent\n"
        "@@PEE:DONE\n"
    )
    checks, _ = pee_parse.parse_pod_exec_output(out)
    cgroup = checks["cgroup_release_agent"]
    assert cgroup["release_agent_writable"] is False
    assert cgroup["controllers"] == {"memory": "absent", "pids": "absent"}


def test_cgroup_block_missing_entirely_is_absent_from_checks():
    checks, _ = pee_parse.parse_pod_exec_output(
        "@@PEE:BEGIN docker_socket\nsocket absent\n@@PEE:END docker_socket\n@@PEE:DONE\n"
    )
    assert "cgroup_release_agent" not in checks


# ---------------------------------------------------------------------------
# parse_pod_exec_output / parse_pod_exec_result
# ---------------------------------------------------------------------------


def test_parse_absent_fixture():
    checks, complete = pee_parse.parse_pod_exec_output(ABSENT_OUTPUT)
    assert complete is True
    assert checks["service_account_token"] == {
        "token_file": "absent",
        "token_present": False,
        "namespace_file": "absent",
    }
    assert checks["docker_socket"] == {"socket_present": False}
    assert checks["capabilities"]["effective_capabilities"] == []
    assert checks["cgroup_release_agent"] == {"cgroup_version": "v2"}


def test_parse_present_fixture_returns_token_in_full_and_decodes_caps():
    checks, complete = pee_parse.parse_pod_exec_output(PRESENT_OUTPUT)
    assert complete is True

    sa = checks["service_account_token"]
    assert sa["token_present"] is True
    assert sa["token_size_bytes"] == 92
    assert sa["token"].startswith("eyJhbGciOiJSUzI1NiJ9.")
    assert sa["token"].endswith("c2lnbmF0dXJl")
    assert sa["namespace_file"] == "present"
    assert sa["pod_namespace"] == "default"

    assert checks["docker_socket"] == {"socket_present": True, "writable": True}

    caps = checks["capabilities"]
    assert "CAP_CHOWN" in caps["effective_capabilities"]
    assert "CAP_SETFCAP" in caps["effective_capabilities"]
    assert "CAP_SYS_ADMIN" not in caps["effective_capabilities"]
    assert caps["cap_eff_hex"] == "00000000a80425fb"

    cgroup = checks["cgroup_release_agent"]
    assert cgroup["cgroup_version"] == "v1"
    assert cgroup["controllers"] == {"memory": "writable", "pids": "not_writable"}
    assert cgroup["release_agent_writable"] is True


def test_parse_unreadable_token_has_note_and_no_token_material():
    out = (
        "@@PEE:BEGIN sa_token\n"
        "token_file unreadable\n"
        "namespace_file absent\n"
        "@@PEE:END sa_token\n"
        "@@PEE:BEGIN docker_socket\n"
        "socket present\n"
        "writable no\n"
        "@@PEE:END docker_socket\n"
        "@@PEE:BEGIN capabilities\n"
        "capeff unavailable\n"
        "@@PEE:END capabilities\n"
        "@@PEE:DONE\n"
    )
    checks, complete = pee_parse.parse_pod_exec_output(out)
    assert complete is True
    sa = checks["service_account_token"]
    assert sa["token_present"] is False
    assert "token" not in sa
    assert "not readable" in sa["note"]
    assert checks["docker_socket"] == {"socket_present": True, "writable": False}
    assert checks["capabilities"] == {"status": "unavailable"}


def test_parse_truncated_output_marks_incomplete():
    truncated = PRESENT_OUTPUT.split("@@PEE:BEGIN docker_socket")[0]
    checks, complete = pee_parse.parse_pod_exec_output(truncated)
    assert complete is False
    assert "service_account_token" in checks
    assert "docker_socket" not in checks


def test_parse_result_success_shape():
    raw = pee_parse.RawPodExecResult(
        server=SERVER, namespace="default", pod="web-abc", container="", stdout=PRESENT_OUTPUT
    )
    out = pee_parse.parse_pod_exec_result(raw)
    assert out["status"] == "success"
    assert out["complete"] is True
    assert out["container"] is None
    assert set(out["checks"]) == {
        "service_account_token", "docker_socket", "capabilities", "cgroup_release_agent",
    }


def test_parse_result_nonzero_exit_without_markers_reports_stderr():
    raw = pee_parse.RawPodExecResult(
        server=SERVER,
        namespace="default",
        pod="web-abc",
        stderr='error: unable to upgrade connection: container not found ("app")',
        returncode=1,
    )
    out = pee_parse.parse_pod_exec_result(raw)
    assert out["status"] == "failed"
    assert "container not found" in out["error"]


def test_parse_result_zero_exit_without_markers_reports_no_output():
    raw = pee_parse.RawPodExecResult(server=SERVER, namespace="default", pod="web-abc", stdout="")
    out = pee_parse.parse_pod_exec_result(raw)
    assert out["status"] == "failed"
    assert out["error"] == "no enumeration output received from pod"


def test_parse_result_passes_adapter_error_through():
    raw = pee_parse.RawPodExecResult(server=SERVER, error="kubectl binary not found on PATH")
    out = pee_parse.parse_pod_exec_result(raw)
    assert out == {
        "server": SERVER,
        "namespace": "",
        "pod": "",
        "container": None,
        "status": "failed",
        "error": "kubectl binary not found on PATH",
    }


# ---------------------------------------------------------------------------
# Tool layer and registration
# ---------------------------------------------------------------------------


def test_tool_is_non_destructive_and_has_contract():
    tool = PodExecEnum()
    assert tool.tool_id == "pod_exec_enum"
    assert tool.destructive is False
    assert tool.spec.name == "pod_exec_enum"
    assert tool.required_binary == "kubectl"
    assert tool.scope_param == "server"


def test_tool_run_end_to_end_with_mocked_subprocess():
    tool = PodExecEnum()
    runner = _fake_runner(_completed(stdout=PRESENT_OUTPUT))
    with patch("tradecraft.adapters.pod_exec_enum.execute.find_kubectl_binary", return_value="/usr/bin/kubectl"), \
            patch("tradecraft.adapters.pod_exec_enum.execute.subprocess.run", runner):
        out = tool.run(server=SERVER, token=TOKEN, namespace="default", pod="web-abc")
    assert out["status"] == "success"
    assert out["checks"]["docker_socket"]["writable"] is True
    assert len(runner.calls) == 1
    argv = runner.calls[0][0]
    assert "-c" not in argv[: argv.index("--")]


def test_tool_run_surfaces_validation_failure_as_failed_status():
    tool = PodExecEnum()
    with patch("tradecraft.adapters.pod_exec_enum.execute.find_kubectl_binary", return_value="/usr/bin/kubectl"):
        out = tool.run(server=SERVER, token=TOKEN, namespace="default", pod="--bad")
    assert out["status"] == "failed"
    assert "invalid pod" in out["error"]


def test_tool_is_in_kubernetes_and_post_exploitation_profiles():
    assert "pod_exec_enum" in load_profile("kubernetes")
    assert "pod_exec_enum" in load_profile("post-exploitation")


def test_tool_is_registered():
    from tradecraft.tools.registry import by_name

    assert "pod_exec_enum" in by_name()
    assert isinstance(by_name()["pod_exec_enum"], PodExecEnum)
