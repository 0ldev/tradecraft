from __future__ import annotations

import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tradecraft.adapters.hydra import execute as hydra_execute
from tradecraft.adapters.hydra import parse as hydra_parse
from tradecraft.tools.hydra import Hydra


def test_normalize_service():
    assert hydra_parse.normalize_service("ssh", "192.168.1.1") == "ssh"
    assert hydra_parse.normalize_service("http", "192.168.1.1") == "http-get"
    assert hydra_parse.normalize_service("https", "192.168.1.1") == "https-get"
    assert hydra_parse.normalize_service("/login_admin", "http://examplepaint.com.br") == "http-post-form"
    assert hydra_parse.normalize_service("mysql", "db.local") == "mysql"
    # Empty service against an https:// target infers the https-* module, not http-*.
    assert hydra_parse.normalize_service("", "https://example.com") == "https-post-form"
    assert hydra_parse.normalize_service("", "192.168.1.1") == "ssh"


def test_normalize_service_upgrades_http_module_for_https_target():
    # Explicit http-* module against an https:// target is upgraded to its
    # https-* counterpart instead of attacking the TLS port over plaintext
    # (hydra otherwise warns it is attacking the port "using plain HTTP"
    # when the module stays http-post-form).
    assert hydra_parse.normalize_service("http-post-form", "https://test-pedidos.example.com.br") == "https-post-form"
    assert hydra_parse.normalize_service("http-get", "https://example.com") == "https-get"
    # Bare host:443 with no scheme is treated the same as an explicit https:// scheme.
    assert hydra_parse.normalize_service("http-post-form", "example.com:443") == "https-post-form"
    # Already-correct https-* module, or a target that really is plain HTTP, is untouched.
    assert hydra_parse.normalize_service("https-post-form", "https://example.com") == "https-post-form"
    assert hydra_parse.normalize_service("http-post-form", "http://example.com") == "http-post-form"
    # A malformed service string against an https target still falls back to https-post-form.
    assert hydra_parse.normalize_service("/login:a=b", "https://example.com") == "https-post-form"


def test_target_is_https():
    assert hydra_parse.target_is_https("https://example.com") is True
    assert hydra_parse.target_is_https("http://example.com") is False
    assert hydra_parse.target_is_https("example.com:443") is True
    assert hydra_parse.target_is_https("example.com:8443") is True
    assert hydra_parse.target_is_https("example.com:80") is False
    assert hydra_parse.target_is_https("example.com") is False


def test_parse_target_host_port():
    assert hydra_parse.parse_target_host_port("192.168.1.50") == ("192.168.1.50", None)
    assert hydra_parse.parse_target_host_port("192.168.1.50:2222") == ("192.168.1.50", 2222)
    assert hydra_parse.parse_target_host_port("http://app.local:8080") == ("app.local", 8080)
    assert hydra_parse.parse_target_host_port("https://app.local") == ("app.local", 443)


def test_bound_credential_lists_caps_attempts():
    # 1. Defaults bound to <= 50
    users, passes = hydra_parse.bound_credential_lists("", "", max_attempts=50)
    assert len(users) * len(passes) <= 50

    # 2. Hard ceiling: requesting 500 attempts is capped at HARD_MAX_ATTEMPTS (100)
    users, passes = hydra_parse.bound_credential_lists(
        username_input="u1,u2,u3,u4,u5",
        password_input=",".join([f"pass{i}" for i in range(100)]),
        max_attempts=500,
    )
    assert len(users) * len(passes) <= hydra_parse.HARD_MAX_ATTEMPTS
    assert len(users) * len(passes) <= 100

    # 3. Single username can test up to max_attempts passwords
    users, passes = hydra_parse.bound_credential_lists(
        username_input="admin@example.com",
        password_input=",".join([f"pass{i}" for i in range(80)]),
        max_attempts=30,
    )
    assert len(users) == 1
    assert len(passes) == 30
    assert len(users) * len(passes) <= 30


def test_bound_credential_lists_defaults_come_from_bundled_wordlists():
    users, passwords = hydra_parse.bound_credential_lists("", "", max_attempts=100)

    from tradecraft.adapters.wordlists import WORDLISTS_DIR

    expected_users = (WORDLISTS_DIR / "hydra-usernames.txt").read_text().splitlines()
    expected_passwords = (WORDLISTS_DIR / "hydra-passwords.txt").read_text().splitlines()

    assert users == expected_users
    assert passwords == expected_passwords
    assert "admin" in users
    assert "password" in passwords


def test_build_argv():
    # SSH service with custom port
    argv = hydra_execute.build_argv(
        host="192.168.1.1",
        service="ssh",
        user_file="/tmp/users.txt",
        pass_file="/tmp/pass.txt",
        port=2222,
        tasks=4,
    )
    assert argv == [
        "hydra", "-t", "4", "-I",
        "-L", "/tmp/users.txt",
        "-P", "/tmp/pass.txt",
        "-s", "2222",
        "ssh://192.168.1.1",
    ]

    argv_form = hydra_execute.build_argv(
        host="examplepaint.com.br",
        service="http-post-form",
        user_file="/tmp/users.txt",
        pass_file="/tmp/pass.txt",
        form_details="/login:user=^USER^&pass=^PASS^:F=invalid",
    )
    assert argv_form == [
        "hydra", "-t", "4", "-I",
        "-L", "/tmp/users.txt",
        "-P", "/tmp/pass.txt",
        "examplepaint.com.br",
        "http-post-form",
        "/login:user=^USER^&pass=^PASS^:F=invalid",
    ]


def test_parse_hydra_output():
    raw_v9 = (
        "Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak\n"
        "[2223][ssh] host: localhost   misc: (null)   login: testuser   password: weakpass123\n"
        "1 of 1 target completed, 1 valid password found\n"
    )
    creds = hydra_parse.parse_hydra_output(raw_v9)
    assert creds == [{
        "port": 2223,
        "service": "ssh",
        "login": "testuser",
        "password": "weakpass123",
    }]

    raw_legacy = "[80][http-post-form][admin][admin123]\n"
    creds_legacy = hydra_parse.parse_hydra_output(raw_legacy)
    assert creds_legacy == [{
        "port": 80,
        "service": "http-post-form",
        "login": "admin",
        "password": "admin123",
    }]


def test_execute_success():
    proc = subprocess.CompletedProcess(
        args=["hydra"],
        returncode=0,
        stdout="[22][ssh] host: 192.168.1.50   misc: (null)   login: root   password: toor\n",
        stderr="",
    )
    with patch("shutil.which", return_value="/usr/bin/hydra"), patch(
        "subprocess.run", return_value=proc
    ) as mock_run:
        result = hydra_execute.execute(
            target="192.168.1.50",
            service="ssh",
            username="root",
            password_list="toor,admin,root",
            max_attempts=10,
        )

    assert result.error is None
    assert result.returncode == 0
    assert result.attempts_run == 3
    assert "root" in result.stdout
    assert mock_run.call_count == 1


def test_execute_reports_zero_attempts_on_hydra_argument_error():
    # A malformed form_details makes hydra abort on its own argument
    # validation before sending a single credential attempt. attempts_run
    # must say 0, not the precomputed users*passwords cap, or the result
    # misrepresents a validation failure as "48 attempts, no hits."
    proc = subprocess.CompletedProcess(
        args=["hydra"],
        returncode=255,
        stdout="",
        stderr=(
            "[WARNING] you specified port 443 for attacking a http service, however did "
            "not specify the -S ssl switch nor used https-..., therefore using plain HTTP\n"
            "[ERROR] optional parameters must have the format X=value: "
            "//test-pedidos.example.com.br"
        ),
    )
    with patch("shutil.which", return_value="/usr/bin/hydra"), patch(
        "subprocess.run", return_value=proc
    ):
        result = hydra_execute.execute(
            target="https://test-pedidos.example.com.br",
            service="http-post-form",
            username="admin,test",
            password_list="admin,password",
            form_details="/:UserEmail=^USER^&Password=^PASS^&Store=https://x:UserEmail=",
            max_attempts=50,
        )

    assert result.attempts_run == 0
    assert result.returncode == 255


def test_execute_errors():
    assert hydra_execute.execute("").error == "Target cannot be empty"

    with patch("shutil.which", return_value=None):
        assert hydra_execute.execute("192.168.1.1").error == "hydra executable not found on PATH"

    with patch("shutil.which", return_value="/usr/bin/hydra"), patch(
        "subprocess.run", side_effect=subprocess.TimeoutExpired("hydra", 180)
    ):
        res = hydra_execute.execute("192.168.1.1")
        assert "timed out after 180s" in res.error


def test_extract_evidence_and_facts():
    tool = Hydra()
    result = {
        "target": "192.168.1.50:22",
        "service": "ssh",
        "credentials_found": [{"port": 22, "service": "ssh", "login": "root", "password": "toor"}],
        "attempts_run": 5,
    }

    # Evidence
    ev = tool.extract_evidence({"target": "192.168.1.50:22"}, result)
    assert ev is not None
    host, full = ev
    assert host == "192.168.1.50"
    assert full["credentials_found"][0]["login"] == "root"

    facts = tool.extract_facts({"target": "192.168.1.50:22"}, result)
    assert facts == [{
        "host": "192.168.1.50",
        "port": 22,
        "candidate_credentials": "root:toor",
    }]
    assert not any("valid_credentials" in f for f in facts)


def test_run_marks_hits_unverified(monkeypatch):
    tool = Hydra()
    raw = SimpleNamespace(
        error=None, service="ssh", attempts_run=5, returncode=0, stderr="",
        stdout="[22][ssh] host: 192.168.1.50   login: root   password: toor\n",
    )
    monkeypatch.setattr(hydra_execute, "execute", lambda **kw: raw)
    res = tool.run(target="192.168.1.50:22", service="ssh")
    assert res["credentials_found"][0]["status"] == "unverified"
    facts = tool.extract_facts({"target": "192.168.1.50:22"}, res)
    assert facts[0]["candidate_credentials"] == "root:toor"
