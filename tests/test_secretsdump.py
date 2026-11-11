"""Unit tests for the secretsdump adapter and tool. destructive: true, so
these call the adapter/tool directly (the --allow-destructive
runtime gate doesn't apply at this layer)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.secretsdump import execute as sd_execute
from tradecraft.adapters.secretsdump import parse as sd_parse
from tradecraft.tools.secretsdump import Secretsdump

# Real-shaped lines, built from secretsdump.py's own confirmed format
# strings (Impacket v0.13.1, NTDSHashes.__decryptHash /
# __decryptSupplementalInfo):
NTLM_LINE = "CORP.LOCAL\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
EMPTY_NT_LINE = "CORP.LOCAL\\svc_disabled:1105:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
KERBEROS_LINE = (
    "CORP.LOCAL\\krbtgt:aes256-cts-hmac-sha1-96:"
    "3e243e2b4d1e8a6f5c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3"
)


class TestBuildArgv:
    def test_argv_full_dump_with_password(self):
        argv = sd_execute.build_argv(
            target="10.0.0.10", domain="corp.local", username="alice", password="Passw0rd!",
        )
        assert argv == ["secretsdump.py", "-just-dc", "corp.local/alice:Passw0rd!@10.0.0.10"]

    def test_argv_with_hashes_uses_no_pass(self):
        argv = sd_execute.build_argv(
            target="dc01.corp.local", domain="corp.local", username="alice",
            hashes="aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef",
        )
        assert "-hashes" in argv and "-no-pass" in argv
        assert argv[-1] == "corp.local/alice@dc01.corp.local"

    def test_argv_just_dc_user_replaces_bare_just_dc(self):
        argv = sd_execute.build_argv(
            target="10.0.0.10", domain="corp.local", username="alice", password="x",
            just_dc_user="krbtgt",
        )
        assert "-just-dc-user" in argv and argv[argv.index("-just-dc-user") + 1] == "krbtgt"
        assert "-just-dc" not in argv

    def test_argv_defaults_to_bare_just_dc(self):
        argv = sd_execute.build_argv(target="10.0.0.10", domain="corp.local", username="alice", password="x")
        assert "-just-dc" in argv

    def test_argv_dc_ip_always_allowed_regardless_of_target_form(self):
        # Unlike kerberoast, secretsdump's -dc-ip is a pure fallback-default
        # override, not a second value for the same connection slot, so it
        # is never rejected even when target is already an IP.
        argv = sd_execute.build_argv(
            target="10.0.0.10", domain="corp.local", username="alice", password="x", dc_ip="10.0.0.99",
        )
        assert "-dc-ip" in argv and argv[argv.index("-dc-ip") + 1] == "10.0.0.99"


class TestValidation:
    def test_target_rejects_cidr(self):
        assert sd_execute._validate_target("10.0.0.0/24") is not None

    def test_target_rejects_range(self):
        assert sd_execute._validate_target("10.0.0.1-10.0.0.50") is not None

    def test_target_accepts_hyphenated_hostname(self):
        assert sd_execute._validate_target("dc-01.sub.corp.local") is None

    def test_credentials_rejects_both_password_and_hashes(self):
        assert sd_execute._validate_credentials("alice", "pw", "aa:bb", "corp.local") is not None

    def test_credentials_rejects_neither(self):
        assert sd_execute._validate_credentials("alice", "", "", "corp.local") is not None

    def test_just_dc_user_rejects_option_like_value(self):
        assert sd_execute._validate_just_dc_user("-dc-ip") is not None

    def test_just_dc_user_rejects_list(self):
        assert sd_execute._validate_just_dc_user("krbtgt,Administrator") is not None

    def test_just_dc_user_accepts_empty(self):
        assert sd_execute._validate_just_dc_user("") is None

    def test_just_dc_user_accepts_bare_username(self):
        assert sd_execute._validate_just_dc_user("krbtgt") is None

    def test_dc_ip_rejects_non_ip(self):
        assert sd_execute._validate_dc_ip("not-an-ip") is not None


class TestExecuteErrorPaths:
    @patch("tradecraft.adapters.secretsdump.execute.find_secretsdump_binary", return_value=None)
    def test_missing_binary_sets_error(self, _mock_find):
        res = sd_execute.execute(target="10.0.0.10", domain="corp.local", username="alice", password="x")
        assert "secretsdump.py" in (res.error or "")

    def test_bad_target_sets_error_before_any_subprocess(self):
        with patch("tradecraft.adapters.secretsdump.execute.subprocess.run") as mock_run:
            res = sd_execute.execute(target="10.0.0.0/24", domain="corp.local", username="alice", password="x")
        mock_run.assert_not_called()
        assert res.error is not None

    @patch("tradecraft.adapters.secretsdump.execute.find_secretsdump_binary", return_value="/usr/local/bin/secretsdump.py")
    @patch("tradecraft.adapters.secretsdump.execute.subprocess.run")
    def test_full_dump_uses_600s_timeout(self, mock_run, _mock_find):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        sd_execute.execute(target="10.0.0.10", domain="corp.local", username="alice", password="x")
        assert mock_run.call_args.kwargs["timeout"] == 600

    @patch("tradecraft.adapters.secretsdump.execute.find_secretsdump_binary", return_value="/usr/local/bin/secretsdump.py")
    @patch("tradecraft.adapters.secretsdump.execute.subprocess.run")
    def test_just_dc_user_uses_120s_timeout(self, mock_run, _mock_find):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        sd_execute.execute(
            target="10.0.0.10", domain="corp.local", username="alice", password="x", just_dc_user="krbtgt",
        )
        assert mock_run.call_args.kwargs["timeout"] == 120

    @patch("tradecraft.adapters.secretsdump.execute.find_secretsdump_binary", return_value="/usr/local/bin/secretsdump.py")
    @patch("tradecraft.adapters.secretsdump.execute.subprocess.run")
    def test_timeout_sets_error(self, mock_run, _mock_find):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["secretsdump.py"], timeout=600)
        res = sd_execute.execute(target="10.0.0.10", domain="corp.local", username="alice", password="x")
        assert "timed out" in (res.error or "")

    @patch("tradecraft.adapters.secretsdump.execute.find_secretsdump_binary", return_value="/usr/local/bin/secretsdump.py")
    @patch("tradecraft.adapters.secretsdump.execute.subprocess.run")
    def test_password_redacted_from_captured_output(self, mock_run, _mock_find):
        mock_run.return_value = MagicMock(stdout="echo corp.local/alice:Passw0rd!@10.0.0.10\n", stderr="", returncode=0)
        res = sd_execute.execute(target="10.0.0.10", domain="corp.local", username="alice", password="Passw0rd!")
        assert "Passw0rd!" not in res.stdout and "<redacted>" in res.stdout

    @patch("tradecraft.adapters.secretsdump.execute.find_secretsdump_binary", return_value="/usr/local/bin/secretsdump.py")
    @patch("tradecraft.adapters.secretsdump.execute.subprocess.run")
    def test_execute_normalizes_host_port_target(self, mock_run, _mock_find):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        res = sd_execute.execute(target="dc01.corp.local:88", domain="corp.local", username="alice", password="x")
        assert res.target == "dc01.corp.local"


class TestParseDumpedHashes:
    def test_parses_ntlm_line(self):
        dumped = sd_parse.parse_dumped_hashes(NTLM_LINE + "\n")
        assert len(dumped) == 1
        assert dumped[0]["username"] == "CORP.LOCAL\\Administrator"
        assert dumped[0]["hash_type"] == "ntlm"
        assert dumped[0]["hash_value"] == NTLM_LINE

    def test_skips_empty_nt_hash(self):
        dumped = sd_parse.parse_dumped_hashes(EMPTY_NT_LINE + "\n")
        assert dumped == []

    def test_parses_kerberos_key_line(self):
        dumped = sd_parse.parse_dumped_hashes(KERBEROS_LINE + "\n")
        assert len(dumped) == 1
        assert dumped[0]["username"] == "CORP.LOCAL\\krbtgt"
        assert dumped[0]["hash_type"] == "aes256-cts-hmac-sha1-96"
        assert dumped[0]["hash_value"] == KERBEROS_LINE

    def test_mixed_output_parses_both_shapes_and_skips_empty(self):
        stdout = f"{NTLM_LINE}\n{EMPTY_NT_LINE}\n[*] Kerberos keys grabbed\n{KERBEROS_LINE}\n"
        dumped = sd_parse.parse_dumped_hashes(stdout)
        assert len(dumped) == 2
        assert {d["hash_type"] for d in dumped} == {"ntlm", "aes256-cts-hmac-sha1-96"}


class TestDetectError:
    def test_detects_connection_refused(self):
        assert sd_parse.detect_secretsdump_error("", "[Errno 111] Connection refused") is not None

    def test_dcsync_denied_is_detected_separately(self):
        assert sd_parse.detect_dcsync_denied("", "[-] Replication access was denied.") is True
        assert sd_parse.detect_secretsdump_error("", "[-] Replication access was denied.") is None


class TestParseResult:
    def test_dcsync_denied_is_reason_not_error(self):
        raw = sd_parse.RawSecretsdumpResult(
            target="10.0.0.10", domain="corp.local", stderr="[-] Replication access was denied.",
        )
        result = sd_parse.parse_secretsdump_result(raw)
        assert "error" not in result and "reason" in result

    def test_connection_failure_is_error(self):
        raw = sd_parse.RawSecretsdumpResult(
            target="10.0.0.10", domain="corp.local", stderr="[Errno 111] Connection refused",
        )
        result = sd_parse.parse_secretsdump_result(raw)
        assert "error" in result

    def test_success_with_dumped_hashes(self):
        raw = sd_parse.RawSecretsdumpResult(
            target="10.0.0.10", domain="corp.local", stdout=f"{NTLM_LINE}\n{KERBEROS_LINE}\n",
        )
        result = sd_parse.parse_secretsdump_result(raw)
        assert "error" not in result and "reason" not in result
        assert result["total_dumped"] == 2
        assert result["total_accounts"] == 2  # Administrator, krbtgt
        assert result["truncated"] is False
        assert result["_full_evidence"]["dumped_hashes"] == result["dumped_hashes"]

    def test_total_accounts_counts_distinct_usernames_not_entries(self):
        # krbtgt gets one NTLM entry plus one entry per Kerberos key type it
        # has -- total_dumped (entry count) must not be used as "accounts
        # dumped", since that overstates how many distinct accounts were
        # actually compromised.
        krbtgt_ntlm = NTLM_LINE.replace("Administrator", "krbtgt")
        krbtgt_aes128 = KERBEROS_LINE.replace("aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96")
        raw = sd_parse.RawSecretsdumpResult(
            target="10.0.0.10", domain="corp.local",
            stdout=f"{krbtgt_ntlm}\n{KERBEROS_LINE}\n{krbtgt_aes128}\n",
        )
        result = sd_parse.parse_secretsdump_result(raw)
        assert result["total_dumped"] == 3
        assert result["total_accounts"] == 1

    def test_nothing_dumped_is_reason_not_error(self):
        raw = sd_parse.RawSecretsdumpResult(target="10.0.0.10", domain="corp.local", stdout="")
        result = sd_parse.parse_secretsdump_result(raw)
        assert "error" not in result and "reason" in result

    def test_caps_at_100_with_truncation_flag(self):
        lines = "\n".join(NTLM_LINE.replace("Administrator", f"user{i}") for i in range(120))
        raw = sd_parse.RawSecretsdumpResult(target="10.0.0.10", domain="corp.local", stdout=lines)
        result = sd_parse.parse_secretsdump_result(raw)
        assert result["total_dumped"] == 120
        assert result["total_accounts"] == 120
        assert len(result["dumped_hashes"]) == 100
        assert result["truncated"] is True
        assert len(result["_full_evidence"]["dumped_hashes"]) == 120

    def test_explicit_error_short_circuits(self):
        raw = sd_parse.RawSecretsdumpResult(target="10.0.0.10", domain="corp.local", error="binary not found")
        result = sd_parse.parse_secretsdump_result(raw)
        assert result["error"] == "binary not found"


class TestToolGlue:
    @patch("tradecraft.adapters.secretsdump.execute.find_secretsdump_binary", return_value="/usr/local/bin/secretsdump.py")
    @patch("tradecraft.adapters.secretsdump.execute.subprocess.run")
    def test_tool_run_success_end_to_end(self, mock_run, _mock_find):
        mock_run.return_value = MagicMock(stdout=NTLM_LINE + "\n", stderr="", returncode=0)
        result = Secretsdump().run(target="10.0.0.10", domain="corp.local", username="alice", password="x")
        assert "error" not in result
        assert result["total_dumped"] == 1
        assert result["total_accounts"] == 1

    def test_tool_is_destructive(self):
        assert Secretsdump().destructive is True

    def test_tool_extract_facts_empty_on_error(self):
        assert Secretsdump().extract_facts({"target": "10.0.0.10"}, {"error": "boom"}) == []

    def test_tool_extract_facts_on_success(self):
        facts = Secretsdump().extract_facts({"target": "10.0.0.10"}, {"total_dumped": 5, "total_accounts": 3})
        assert facts == [{"host": "10.0.0.10", "port": 445, "secretsdump_accounts_dumped": 3}]

    def test_tool_extract_facts_strips_port_suffix(self):
        facts = Secretsdump().extract_facts(
            {"target": "dc01.corp.local:88"}, {"total_dumped": 1, "total_accounts": 1},
        )
        assert facts == [{"host": "dc01.corp.local", "port": 445, "secretsdump_accounts_dumped": 1}]
