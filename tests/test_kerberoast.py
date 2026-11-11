"""Unit tests for the kerberoast adapter and tool. destructive: true, so
these call the adapter/tool directly (the --allow-destructive
runtime gate doesn't apply at this layer)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.kerberoast import execute as kb_execute
from tradecraft.adapters.kerberoast import parse as kb_parse
from tradecraft.tools.kerberoast import Kerberoast

# Real-shaped $krb5tgs$ lines, built from GetUserSPNs.py's own confirmed
# format strings (Impacket v0.13.1, outputTGS()) -- not hand-waved:
#   RC4/DES:    $krb5tgs$<etype>$*<user>$<realm>$<spn~tilde>*$<checksum>$<data>
#   AES128/256: $krb5tgs$<etype>$<user>$<realm>$*<spn~tilde>*$<checksum>$<data>
RC4_HASH_LINE = (
    "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc~dbserver.corp.local~1433*"
    "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)
AES256_HASH_LINE = (
    "$krb5tgs$18$svc_web$CORP.LOCAL$*HTTP~webserver.corp.local~443*"
    "$cccccccccccccccccccccccc$dddddddddddddddddddddddddddddddddddddd"
)


class TestBuildArgv:
    def test_argv_with_password(self):
        argv = kb_execute.build_argv(
            target="10.0.0.10", domain="corp.local", username="alice", password="Passw0rd!",
        )
        assert argv == ["GetUserSPNs.py", "-request", "corp.local/alice:Passw0rd!", "-dc-ip", "10.0.0.10"]

    def test_argv_with_hashes_uses_no_pass(self):
        argv = kb_execute.build_argv(
            target="dc01.corp.local", domain="corp.local", username="alice",
            hashes="aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef",
        )
        assert "corp.local/alice" in argv
        assert "-hashes" in argv
        assert argv[argv.index("-hashes") + 1] == "aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef"
        assert "-no-pass" in argv
        assert "-dc-host" in argv and argv[argv.index("-dc-host") + 1] == "dc01.corp.local"

    def test_argv_always_passes_request(self):
        argv = kb_execute.build_argv(target="10.0.0.10", domain="corp.local", username="alice", password="x")
        assert "-request" in argv

    def test_argv_ip_target_uses_dc_ip_hostname_target_uses_dc_host(self):
        ip_argv = kb_execute.build_argv(target="10.0.0.10", domain="corp.local", username="a", password="x")
        assert "-dc-ip" in ip_argv and "-dc-host" not in ip_argv

        host_argv = kb_execute.build_argv(target="dc01.corp.local", domain="corp.local", username="a", password="x")
        assert "-dc-host" in host_argv and "-dc-ip" not in host_argv

    def test_argv_explicit_dc_ip_overrides_resolution(self):
        argv = kb_execute.build_argv(
            target="dc01.corp.local", domain="corp.local", username="a", password="x", dc_ip="10.0.0.99",
        )
        assert "-dc-host" in argv
        assert "-dc-ip" in argv and argv[argv.index("-dc-ip") + 1] == "10.0.0.99"


class TestValidation:
    def test_target_rejects_cidr(self):
        assert kb_execute._validate_target("10.0.0.0/24") is not None

    def test_target_rejects_list(self):
        assert kb_execute._validate_target("10.0.0.1,10.0.0.2") is not None

    def test_target_rejects_range(self):
        assert kb_execute._validate_target("10.0.0.1-10.0.0.50") is not None

    def test_target_accepts_single_ip_or_host(self):
        assert kb_execute._validate_target("10.0.0.10") is None
        assert kb_execute._validate_target("dc01.corp.local") is None

    def test_target_accepts_hyphenated_hostname_with_several_labels(self):
        # A naive "has a hyphen and several dots" heuristic would wrongly
        # reject this as an IP range; it's a perfectly normal hostname.
        assert kb_execute._validate_target("dc-01.sub.corp.local") is None

    def test_credentials_rejects_both_password_and_hashes(self):
        err = kb_execute._validate_credentials("alice", "pw", "aa:bb", "corp.local")
        assert err is not None and "not both" in err

    def test_credentials_rejects_neither(self):
        err = kb_execute._validate_credentials("alice", "", "", "corp.local")
        assert err is not None and "required" in err

    def test_credentials_requires_username(self):
        err = kb_execute._validate_credentials("", "pw", "", "corp.local")
        assert err is not None

    def test_username_upn_matching_domain_is_stripped(self):
        user, err = kb_execute._normalize_username("alice@corp.local", "corp.local")
        assert err is None and user == "alice"

    def test_username_upn_mismatched_domain_is_rejected(self):
        user, err = kb_execute._normalize_username("alice@other.local", "corp.local")
        assert user is None and err is not None

    def test_username_downlevel_form_matching_full_domain(self):
        user, err = kb_execute._normalize_username("corp.local\\alice", "corp.local")
        assert err is None and user == "alice"

    def test_username_netbios_short_name_is_rejected(self):
        # A NetBIOS short name ('CORP') is not the DNS domain
        # ('corp.local'), and this codebase doesn't map one to the other
        # (certipy_enum's own _normalize_username has the identical,
        # deliberate behavior, with its own test confirming it) -- so
        # this must be rejected, not silently accepted.
        user, err = kb_execute._normalize_username("CORP\\alice", "corp.local")
        assert user is None and err is not None

    def test_dc_ip_rejects_non_ip(self):
        assert kb_execute._validate_dc_ip("not-an-ip", "dc01.corp.local") is not None

    def test_dc_ip_accepts_empty(self):
        assert kb_execute._validate_dc_ip("", "dc01.corp.local") is None

    def test_dc_ip_accepted_with_hostname_target(self):
        assert kb_execute._validate_dc_ip("10.0.0.99", "dc01.corp.local") is None

    def test_dc_ip_rejected_with_ip_target(self):
        # dc_ip overrides DNS resolution for a hostname target; it's
        # meaningless (and would otherwise silently emit -dc-ip twice)
        # when target is already an IP.
        err = kb_execute._validate_dc_ip("10.0.0.99", "10.0.0.10")
        assert err is not None and "hostname" in err


class TestExecuteErrorPaths:
    @patch("tradecraft.adapters.kerberoast.execute.find_kerberoast_binary", return_value=None)
    def test_missing_binary_sets_error(self, _mock_find):
        res = kb_execute.execute(target="10.0.0.10", domain="corp.local", username="alice", password="x")
        assert "GetUserSPNs.py" in (res.error or "")

    def test_bad_target_sets_error_before_any_subprocess(self):
        with patch("tradecraft.adapters.kerberoast.execute.subprocess.run") as mock_run:
            res = kb_execute.execute(target="10.0.0.0/24", domain="corp.local", username="alice", password="x")
        mock_run.assert_not_called()
        assert res.error is not None

    def test_credential_error_before_any_subprocess(self):
        with patch("tradecraft.adapters.kerberoast.execute.subprocess.run") as mock_run:
            res = kb_execute.execute(target="10.0.0.10", domain="corp.local", username="alice")
        mock_run.assert_not_called()
        assert res.error is not None

    @patch("tradecraft.adapters.kerberoast.execute.find_kerberoast_binary", return_value="/usr/local/bin/GetUserSPNs.py")
    @patch("tradecraft.adapters.kerberoast.execute.subprocess.run")
    def test_timeout_sets_error(self, mock_run, _mock_find):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["GetUserSPNs.py"], timeout=60)
        res = kb_execute.execute(target="10.0.0.10", domain="corp.local", username="alice", password="x")
        assert "timed out" in (res.error or "")

    @patch("tradecraft.adapters.kerberoast.execute.find_kerberoast_binary", return_value="/usr/local/bin/GetUserSPNs.py")
    @patch("tradecraft.adapters.kerberoast.execute.subprocess.run")
    def test_password_redacted_from_captured_output(self, mock_run, _mock_find):
        mock_run.return_value = MagicMock(
            stdout="some debug echo of corp.local/alice:Passw0rd!\n", stderr="", returncode=0,
        )
        res = kb_execute.execute(target="10.0.0.10", domain="corp.local", username="alice", password="Passw0rd!")
        assert "Passw0rd!" not in res.stdout
        assert "<redacted>" in res.stdout


class TestParseHashes:
    def test_parses_rc4_shape(self):
        hashes = kb_parse.parse_krb5tgs_hashes(RC4_HASH_LINE + "\n")
        assert len(hashes) == 1
        assert hashes[0]["username"] == "svc_sql"
        assert hashes[0]["spn"] == "MSSQLSvc:dbserver.corp.local:1433"
        assert hashes[0]["hash_value"] == RC4_HASH_LINE

    def test_parses_aes_shape(self):
        hashes = kb_parse.parse_krb5tgs_hashes(AES256_HASH_LINE + "\n")
        assert len(hashes) == 1
        assert hashes[0]["username"] == "svc_web"
        assert hashes[0]["spn"] == "HTTP:webserver.corp.local:443"
        assert hashes[0]["hash_value"] == AES256_HASH_LINE

    def test_ignores_non_hash_lines(self):
        stdout = "Impacket v0.13.1\nServicePrincipalName  Name\n" + RC4_HASH_LINE
        hashes = kb_parse.parse_krb5tgs_hashes(stdout)
        assert len(hashes) == 1

    def test_no_entries_found_yields_empty_list(self):
        assert kb_parse.parse_krb5tgs_hashes("No entries found!\n") == []


class TestDetectError:
    def test_detects_connection_refused(self):
        assert kb_parse.detect_kerberoast_error("", "[Errno 111] Connection refused") is not None

    def test_detects_kdc_err(self):
        assert kb_parse.detect_kerberoast_error("KDC_ERR_C_PRINCIPAL_UNKNOWN", "") is not None

    def test_clean_stdout_with_no_entries_is_not_an_error(self):
        assert kb_parse.detect_kerberoast_error("No entries found!\n", "") is None

    def test_clean_stdout_with_hashes_is_not_an_error(self):
        assert kb_parse.detect_kerberoast_error(RC4_HASH_LINE, "") is None


class TestParseResult:
    def test_no_entries_found_is_reason_not_error(self):
        raw = kb_parse.RawKerberoastResult(target="10.0.0.10", domain="corp.local", stdout="No entries found!\n")
        result = kb_parse.parse_kerberoast_result(raw)
        assert "error" not in result
        assert "reason" in result

    def test_connection_failure_is_error_despite_returncode_zero(self):
        # GetUserSPNs.py always exits 0 even on failure -- confirmed against
        # the real installed script's top-level exception handler.
        raw = kb_parse.RawKerberoastResult(
            target="10.0.0.10", domain="corp.local", returncode=0,
            stderr="[Errno 111] Connection refused",
        )
        result = kb_parse.parse_kerberoast_result(raw)
        assert "error" in result

    def test_success_with_hashes(self):
        raw = kb_parse.RawKerberoastResult(
            target="10.0.0.10", domain="corp.local",
            stdout=f"{RC4_HASH_LINE}\n{AES256_HASH_LINE}\n",
        )
        result = kb_parse.parse_kerberoast_result(raw)
        assert "error" not in result and "reason" not in result
        assert result["total_hashes"] == 2
        assert len(result["hashes"]) == 2
        assert result["truncated"] is False
        assert result["_full_evidence"]["hashes"] == result["hashes"]

    def test_caps_at_50_with_truncation_flag(self):
        lines = "\n".join(
            RC4_HASH_LINE.replace("svc_sql", f"svc_{i}") for i in range(60)
        )
        raw = kb_parse.RawKerberoastResult(target="10.0.0.10", domain="corp.local", stdout=lines)
        result = kb_parse.parse_kerberoast_result(raw)
        assert result["total_hashes"] == 60
        assert len(result["hashes"]) == 50
        assert result["truncated"] is True
        assert len(result["_full_evidence"]["hashes"]) == 60

    def test_explicit_error_short_circuits(self):
        raw = kb_parse.RawKerberoastResult(target="10.0.0.10", domain="corp.local", error="binary not found")
        result = kb_parse.parse_kerberoast_result(raw)
        assert result["error"] == "binary not found"


class TestToolGlue:
    @patch("tradecraft.adapters.kerberoast.execute.find_kerberoast_binary", return_value="/usr/local/bin/GetUserSPNs.py")
    @patch("tradecraft.adapters.kerberoast.execute.subprocess.run")
    def test_tool_run_success_end_to_end(self, mock_run, _mock_find):
        mock_run.return_value = MagicMock(stdout=RC4_HASH_LINE + "\n", stderr="", returncode=0)
        result = Kerberoast().run(target="10.0.0.10", domain="corp.local", username="alice", password="x")
        assert "error" not in result
        assert result["total_hashes"] == 1

    @patch("tradecraft.adapters.kerberoast.execute.find_kerberoast_binary", return_value=None)
    def test_tool_run_maps_execution_error(self, _mock_find):
        result = Kerberoast().run(target="10.0.0.10", domain="corp.local", username="alice", password="x")
        assert "error" in result

    def test_tool_is_destructive(self):
        assert Kerberoast().destructive is True

    def test_tool_extract_facts_empty_on_error(self):
        facts = Kerberoast().extract_facts({"target": "10.0.0.10"}, {"error": "boom"})
        assert facts == []

    def test_tool_extract_facts_on_success(self):
        facts = Kerberoast().extract_facts(
            {"target": "10.0.0.10"}, {"total_hashes": 2, "hashes": []},
        )
        assert facts == [{"host": "10.0.0.10", "port": 88, "kerberoastable_accounts": 2}]

    def test_tool_extract_facts_strips_port_suffix(self):
        # A host:port target must key the FactStore under the bare host, the
        # same as certipy_enum/bloodhound, so it merges onto the same record
        # another tool reports for this DC rather than fragmenting it.
        facts = Kerberoast().extract_facts(
            {"target": "dc01.corp.local:88"}, {"total_hashes": 1, "hashes": []},
        )
        assert facts == [{"host": "dc01.corp.local", "port": 88, "kerberoastable_accounts": 1}]

    def test_tool_extract_evidence_strips_port_suffix(self):
        host, _ = Kerberoast().extract_evidence(
            {"target": "dc01.corp.local:88"}, {"_full_evidence": {"hashes": []}},
        )
        assert host == "dc01.corp.local"


class TestTargetNormalization:
    def test_execute_normalizes_host_port_target(self):
        with patch("tradecraft.adapters.kerberoast.execute.find_kerberoast_binary",
                   return_value="/usr/local/bin/GetUserSPNs.py"), \
             patch("tradecraft.adapters.kerberoast.execute.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="No entries found!\n", stderr="", returncode=0)
            res = kb_execute.execute(target="dc01.corp.local:88", domain="corp.local", username="a", password="x")
        assert res.target == "dc01.corp.local"
        argv = mock_run.call_args.args[0]
        assert "dc01.corp.local" in argv
        assert "dc01.corp.local:88" not in argv
