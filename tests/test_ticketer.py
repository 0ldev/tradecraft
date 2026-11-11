"""Unit tests for the ticketer adapter and tool. destructive: true, so
these call the adapter/tool directly (the --allow-destructive
runtime gate doesn't apply at this layer)."""
import base64
import os
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.ticketer import execute as tk_execute
from tradecraft.adapters.ticketer import parse as tk_parse
from tradecraft.tools.ticketer import Ticketer

VALID_SID = "S-1-5-21-111111111-222222222-333333333"
NT_HASH = "aabbccddeeff00112233445566778899"  # 32 hex chars
AES256_KEY = "a" * 64


def _fake_run_creates_ccache(argv, **kwargs):
    cwd = kwargs.get("cwd")
    username = argv[-1]
    fname = tk_parse.ccache_filename(username)
    with open(os.path.join(cwd, fname), "wb") as f:
        f.write(b"FAKE_CCACHE_BYTES")
    return MagicMock(stdout="", stderr="", returncode=0)


class TestValidateDomainSid:
    def test_accepts_valid_domain_sid(self):
        assert tk_parse.validate_domain_sid(VALID_SID) is None

    def test_rejects_empty(self):
        assert tk_parse.validate_domain_sid("") is not None

    def test_rejects_trailing_rid(self):
        # A user/group SID (e.g. Administrator's well-known RID 500) is a
        # common copy-paste mistake, explicitly called out by the doc.
        assert tk_parse.validate_domain_sid(VALID_SID + "-500") is not None


class TestValidateKrbtgtHash:
    def test_ntlm_accepts_32_hex_chars(self):
        assert tk_parse.validate_krbtgt_hash(NT_HASH, "ntlm") is None

    def test_ntlm_rejects_wrong_length(self):
        assert tk_parse.validate_krbtgt_hash(NT_HASH + "ff", "ntlm") is not None

    def test_aes256_accepts_64_hex_chars(self):
        assert tk_parse.validate_krbtgt_hash(AES256_KEY, "aes256-cts-hmac-sha1-96") is None

    def test_aes128_accepts_32_hex_chars(self):
        assert tk_parse.validate_krbtgt_hash(NT_HASH, "aes128-cts-hmac-sha1-96") is None

    def test_rejects_non_hex(self):
        assert tk_parse.validate_krbtgt_hash("not-hex-zzzz", "ntlm") is not None

    def test_rejects_unknown_hash_type(self):
        assert tk_parse.validate_krbtgt_hash(NT_HASH, "sha256") is not None

    def test_rejects_empty(self):
        assert tk_parse.validate_krbtgt_hash("", "ntlm") is not None


class TestValidateUsername:
    def test_accepts_empty_for_default_substitution(self):
        assert tk_parse.validate_username("") is None

    def test_rejects_option_like_value(self):
        assert tk_parse.validate_username("-domain") is not None

    def test_rejects_list(self):
        assert tk_parse.validate_username("Administrator,krbtgt") is not None


class TestCcacheFilename:
    def test_simple_username(self):
        assert tk_parse.ccache_filename("Administrator") == "Administrator.ccache"

    def test_slash_replaced_with_dot(self):
        assert tk_parse.ccache_filename("corp.local/Administrator") == "corp.local.Administrator.ccache"


class TestBuildArgv:
    def test_ntlm_uses_nthash(self):
        argv = tk_execute.build_argv(
            domain="corp.local", domain_sid=VALID_SID, krbtgt_hash=NT_HASH,
            hash_type="ntlm", username="Administrator",
        )
        assert argv == [
            "ticketer.py", "-domain", "corp.local", "-domain-sid", VALID_SID,
            "-nthash", NT_HASH, "Administrator",
        ]

    def test_aes_uses_aeskey(self):
        argv = tk_execute.build_argv(
            domain="corp.local", domain_sid=VALID_SID, krbtgt_hash=AES256_KEY,
            hash_type="aes256-cts-hmac-sha1-96", username="Administrator",
        )
        assert "-aesKey" in argv and argv[argv.index("-aesKey") + 1] == AES256_KEY
        assert "-nthash" not in argv

    def test_no_request_no_spn_no_network_auth_flags(self):
        # Pure offline forge: none of the KDC-round-trip-only flags should
        # ever appear.
        argv = tk_execute.build_argv(
            domain="corp.local", domain_sid=VALID_SID, krbtgt_hash=NT_HASH,
            hash_type="ntlm", username="Administrator",
        )
        for forbidden in ("-request", "-spn", "-user", "-password", "-hashes", "-dc-ip"):
            assert forbidden not in argv

    def test_username_is_final_positional(self):
        argv = tk_execute.build_argv(
            domain="corp.local", domain_sid=VALID_SID, krbtgt_hash=NT_HASH,
            hash_type="ntlm", username="krbtgt",
        )
        assert argv[-1] == "krbtgt"


class TestExecuteValidation:
    def test_bad_domain_sid_before_any_subprocess(self):
        with patch("tradecraft.adapters.ticketer.execute.subprocess.run") as mock_run:
            res = tk_execute.execute(domain="corp.local", krbtgt_hash=NT_HASH, domain_sid="not-a-sid")
        mock_run.assert_not_called()
        assert res.error is not None

    def test_bad_krbtgt_hash_before_any_subprocess(self):
        with patch("tradecraft.adapters.ticketer.execute.subprocess.run") as mock_run:
            res = tk_execute.execute(domain="corp.local", krbtgt_hash="zz", domain_sid=VALID_SID)
        mock_run.assert_not_called()
        assert res.error is not None

    def test_username_defaults_to_administrator(self):
        with patch("tradecraft.adapters.ticketer.execute.find_ticketer_binary", return_value=None):
            res = tk_execute.execute(domain="corp.local", krbtgt_hash=NT_HASH, domain_sid=VALID_SID)
        assert res.username == "Administrator"

    @patch("tradecraft.adapters.ticketer.execute.find_ticketer_binary", return_value=None)
    def test_missing_binary_sets_error(self, _mock_find):
        res = tk_execute.execute(domain="corp.local", krbtgt_hash=NT_HASH, domain_sid=VALID_SID)
        assert "ticketer.py" in (res.error or "")


class TestExecuteSubprocess:
    @patch("tradecraft.adapters.ticketer.execute.find_ticketer_binary", return_value="/usr/local/bin/ticketer.py")
    @patch("tradecraft.adapters.ticketer.execute.subprocess.run")
    def test_success_reads_and_base64_encodes_ccache(self, mock_run, _mock_find):
        mock_run.side_effect = _fake_run_creates_ccache
        res = tk_execute.execute(domain="corp.local", krbtgt_hash=NT_HASH, domain_sid=VALID_SID)
        assert res.error is None
        assert base64.b64decode(res.ccache_b64) == b"FAKE_CCACHE_BYTES"

    @patch("tradecraft.adapters.ticketer.execute.find_ticketer_binary", return_value="/usr/local/bin/ticketer.py")
    @patch("tradecraft.adapters.ticketer.execute.subprocess.run")
    def test_krb5ccname_cleared_from_subprocess_env(self, mock_run, _mock_find):
        mock_run.side_effect = _fake_run_creates_ccache
        with patch.dict(os.environ, {"KRB5CCNAME": "/some/leftover/ccache"}):
            tk_execute.execute(domain="corp.local", krbtgt_hash=NT_HASH, domain_sid=VALID_SID)
        passed_env = mock_run.call_args.kwargs["env"]
        assert "KRB5CCNAME" not in passed_env

    @patch("tradecraft.adapters.ticketer.execute.find_ticketer_binary", return_value="/usr/local/bin/ticketer.py")
    @patch("tradecraft.adapters.ticketer.execute.subprocess.run")
    def test_nonzero_returncode_sets_error(self, mock_run, _mock_find):
        mock_run.return_value = MagicMock(stdout="", stderr="[-] Invalid key length", returncode=1)
        res = tk_execute.execute(domain="corp.local", krbtgt_hash=NT_HASH, domain_sid=VALID_SID)
        assert res.error is not None and "Invalid key length" in res.error

    @patch("tradecraft.adapters.ticketer.execute.find_ticketer_binary", return_value="/usr/local/bin/ticketer.py")
    @patch("tradecraft.adapters.ticketer.execute.subprocess.run")
    def test_success_exit_but_no_ccache_file_sets_error(self, mock_run, _mock_find):
        # subprocess reports success but never wrote the expected file.
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        res = tk_execute.execute(domain="corp.local", krbtgt_hash=NT_HASH, domain_sid=VALID_SID)
        assert res.error is not None and "no ccache" in res.error

    @patch("tradecraft.adapters.ticketer.execute.find_ticketer_binary", return_value="/usr/local/bin/ticketer.py")
    @patch("tradecraft.adapters.ticketer.execute.subprocess.run")
    def test_timeout_sets_error(self, mock_run, _mock_find):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["ticketer.py"], timeout=60)
        res = tk_execute.execute(domain="corp.local", krbtgt_hash=NT_HASH, domain_sid=VALID_SID)
        assert "timed out" in (res.error or "")

    @patch("tradecraft.adapters.ticketer.execute.find_ticketer_binary", return_value="/usr/local/bin/ticketer.py")
    @patch("tradecraft.adapters.ticketer.execute.subprocess.run")
    def test_krbtgt_hash_redacted_from_captured_output(self, mock_run, _mock_find):
        mock_run.return_value = MagicMock(stdout=f"debug: using key {NT_HASH}\n", stderr="", returncode=1)
        res = tk_execute.execute(domain="corp.local", krbtgt_hash=NT_HASH, domain_sid=VALID_SID)
        assert NT_HASH not in res.stdout
        assert "<redacted>" in res.stdout


class TestToolGlue:
    @patch("tradecraft.adapters.ticketer.execute.find_ticketer_binary", return_value="/usr/local/bin/ticketer.py")
    @patch("tradecraft.adapters.ticketer.execute.subprocess.run")
    def test_tool_run_success_end_to_end(self, mock_run, _mock_find):
        mock_run.side_effect = _fake_run_creates_ccache
        result = Ticketer().run(domain="corp.local", domain_sid=VALID_SID, krbtgt_hash=NT_HASH)
        assert "error" not in result
        assert base64.b64decode(result["ccache_b64"]) == b"FAKE_CCACHE_BYTES"
        assert result["username"] == "Administrator"

    @patch("tradecraft.adapters.ticketer.execute.find_ticketer_binary", return_value=None)
    def test_tool_run_maps_execution_error(self, _mock_find):
        result = Ticketer().run(domain="corp.local", domain_sid=VALID_SID, krbtgt_hash=NT_HASH)
        assert "error" in result

    def test_tool_is_destructive(self):
        assert Ticketer().destructive is True

    def test_tool_extract_facts_always_empty(self):
        # No network target at all for this tool.
        assert Ticketer().extract_facts({}, {"ccache_b64": "x"}) == []
