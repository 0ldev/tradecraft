"""Unit tests for trufflehog adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.trufflehog.execute import (
    ASPNET_DETECTORS_CONFIG,
    RawTruffleHogResult,
    build_argv,
    build_git_argv,
    execute,
    materialize_urls,
)
from tradecraft.adapters.trufflehog.parse import (
    _mask_raw_secret,
    host_port_from_target,
    parse_trufflehog_output,
)

REAL_CAPTURED_TRUFFLEHOG_STDOUT = """{"level":"info-0","ts":"2026-11-01T19:36:08Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"9fRvU","job_id":1,"source_id":1,"source_name":"trufflehog - filesystem","source_type":"SOURCE_TYPE_FILESYSTEM","with_units":true}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_test/test.js","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":13,"DetectorName":"Slack","DetectorDescription":"Slack tokens can be used to authenticate API requests to the Slack platform, allowing access to various workspace resources and functionalities.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"xoxb-EXAMPLE00-EXAMPLE000000-EXAMPLEFAKETOKENFAKETOKENFAKETOKEN0","RawV2":"","Redacted":"","ExtraData":{"rotation_guide":"https://howtorotate.com/docs/tutorials/slack/","token_type":"Slack Bot Token"},"StructuredData":null,"SecretParts":{"key":"xoxb-EXAMPLE00-EXAMPLE000000-EXAMPLEFAKETOKENFAKETOKENFAKETOKEN0"}}
{"level":"info-0","ts":"2026-11-01T19:36:08Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":65,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"2.477323ms","trufflehog_version":"3.99.7","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
"""

# Real captured output from `trufflehog filesystem web.config
# --config=config/trufflehog_detectors/aspnet_machinekey.yaml
# --no-verification --json --no-update` (v3.99.7). Confirms two things
# trufflehog's own docs get wrong/unclear: every custom-regex-config hit
# reports DetectorName:"CustomRegex" literally (never the detector's own
# `name`), and the real name only appears in ExtraData.name.
REAL_CAPTURED_ASPNET_MACHINEKEY_STDOUT = """{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/aspnet_test/web.config","line":5}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":904,"DetectorName":"CustomRegex","DetectorDescription":"ASP.NET machineKey validation attribute -- the HMAC algorithm (ysoserial.net's --validationalg) a forged payload must match.\\n","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"HMACSHA256","RawV2":"","Redacted":"","ExtraData":{"name":"ASPNETValidationAlgorithm"},"StructuredData":null,"SecretParts":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/aspnet_test/web.config","line":4}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":904,"DetectorName":"CustomRegex","DetectorDescription":"ASP.NET machineKey decryptionKey attribute -- needed alongside validationKey to forge an encrypted (not just signed) ViewState payload.\\n","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210","RawV2":"","Redacted":"","ExtraData":{"name":"ASPNETDecryptionKey"},"StructuredData":null,"SecretParts":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/aspnet_test/web.config","line":5}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":904,"DetectorName":"CustomRegex","DetectorDescription":"ASP.NET machineKey decryption attribute -- the symmetric cipher (ysoserial.net's --decryptionalg) a forged encrypted payload must match.\\n","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AES","RawV2":"","Redacted":"","ExtraData":{"name":"ASPNETDecryptionAlgorithm"},"StructuredData":null,"SecretParts":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/aspnet_test/web.config","line":3}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":904,"DetectorName":"CustomRegex","DetectorDescription":"ASP.NET machineKey validationKey attribute -- a leaked static key lets ysoserial.net forge a signed __VIEWSTATE (or Forms-auth ticket) that the target will accept as genuine.\\n","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6","RawV2":"","Redacted":"","ExtraData":{"name":"ASPNETValidationKey"},"StructuredData":null,"SecretParts":null}
"""


class TestTruffleHogExecute:
    def test_build_argv_default(self):
        argv = build_argv("/tmp/scan_dir")
        assert argv == [
            "trufflehog",
            "filesystem",
            "/tmp/scan_dir",
            "--json",
            "--no-update",
            "--no-color",
            f"--config={ASPNET_DETECTORS_CONFIG}",
            "--no-verification",
        ]

    def test_build_argv_verified_with_concurrency(self):
        argv = build_argv("/tmp/scan_dir", verify=True, concurrency=10)
        assert argv == [
            "trufflehog",
            "filesystem",
            "/tmp/scan_dir",
            "--json",
            "--no-update",
            "--no-color",
            f"--config={ASPNET_DETECTORS_CONFIG}",
            "--concurrency", "10",
        ]

    def test_build_argv_omits_config_flag_when_bundled_file_missing(self, monkeypatch):
        monkeypatch.setattr(
            "tradecraft.adapters.trufflehog.execute.ASPNET_DETECTORS_CONFIG",
            "/nonexistent/aspnet_machinekey.yaml",
        )
        argv = build_argv("/tmp/scan_dir")
        assert not any(a.startswith("--config=") for a in argv)

    def test_materialize_urls_fetches_content(self, tmp_path):
        fake_response = MagicMock()
        fake_response.read.return_value = b"const KEY = 'secret123';"
        fake_response.__enter__.return_value = fake_response

        with patch("urllib.request.urlopen", return_value=fake_response):
            fetched = materialize_urls(["https://example.com/app.js"], str(tmp_path))
            assert fetched == ["https://example.com/app.js"]
            files = list(tmp_path.iterdir())
            assert len(files) == 1
            assert files[0].read_bytes() == b"const KEY = 'secret123';"

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "Target cannot be empty"

    @patch("shutil.which", return_value=None)
    def test_execute_missing_binary(self, mock_which):
        res = execute("https://example.com/app.js")
        assert "trufflehog binary not found on PATH" in (res.error or "")

    @patch("shutil.which", return_value="/usr/local/bin/trufflehog")
    @patch("subprocess.run")
    def test_execute_local_directory(self, mock_run, mock_which, tmp_path):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = REAL_CAPTURED_TRUFFLEHOG_STDOUT
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        res = execute(str(tmp_path))
        assert res.error is None
        assert res.returncode == 0
        assert "Slack" in res.stdout

    @patch("shutil.which", return_value="/usr/local/bin/trufflehog")
    @patch("tradecraft.adapters.trufflehog.execute.materialize_urls")
    @patch("subprocess.run")
    def test_execute_remote_urls(self, mock_run, mock_materialize, mock_which):
        mock_materialize.return_value = ["https://example.com/bundle.js"]
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = REAL_CAPTURED_TRUFFLEHOG_STDOUT
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        res = execute("https://example.com/bundle.js")
        assert res.error is None
        assert res.scanned_urls == ["https://example.com/bundle.js"]

    @patch("shutil.which", return_value="/usr/local/bin/trufflehog")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trufflehog", timeout=60))
    def test_execute_timeout(self, mock_run, mock_which, tmp_path):
        res = execute(str(tmp_path), subprocess_timeout=60)
        assert "timed out after 60s" in (res.error or "")


    def test_build_git_argv_default(self):
        argv = build_git_argv("https://github.com/example/repo")
        assert argv == [
            "trufflehog",
            "git",
            "https://github.com/example/repo",
            "--json",
            "--no-color",
            f"--config={ASPNET_DETECTORS_CONFIG}",
            "--no-verification",
        ]

    def test_build_git_argv_verify(self):
        argv = build_git_argv("https://github.com/example/repo", verify=True)
        assert argv == [
            "trufflehog",
            "git",
            "https://github.com/example/repo",
            "--json",
            "--no-color",
            f"--config={ASPNET_DETECTORS_CONFIG}",
        ]

    @patch("shutil.which", return_value="/usr/local/bin/trufflehog")
    @patch("subprocess.run")
    def test_execute_git_history_mode_success(self, mock_run, mock_which):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = REAL_CAPTURED_TRUFFLEHOG_STDOUT
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        res = execute("https://github.com/example/repo", scan_git_history=True)
        assert res.error is None
        assert res.returncode == 0
        assert "Slack" in res.stdout
        mock_run.assert_called_once_with(
            build_git_argv("https://github.com/example/repo", verify=False),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=300,
        )

    @patch("shutil.which", return_value="/usr/local/bin/trufflehog")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trufflehog", timeout=300))
    def test_execute_git_history_mode_timeout(self, mock_run, mock_which):
        res = execute("https://github.com/example/repo", scan_git_history=True)
        assert "timed out against https://github.com/example/repo" in (res.error or "")

    @patch("shutil.which", return_value="/usr/local/bin/trufflehog")
    @patch("subprocess.run", side_effect=RuntimeError("git clone failed"))
    def test_execute_git_history_mode_failure(self, mock_run, mock_which):
        res = execute("https://github.com/example/repo", scan_git_history=True)
        assert "git clone failed" in (res.error or "")


class TestTruffleHogParse:
    def test_mask_raw_secret(self):
        assert _mask_raw_secret("xoxb-EXAMPLE00-EXAMPLE000000-EXAMPLEFAKETOKEN0") == "xoxb-E...KEN0"
        assert _mask_raw_secret("short") == "sh****rt"
        assert _mask_raw_secret("123") == "****"

    def test_host_port_from_target(self):
        assert host_port_from_target("https://example.com/app.js") == ("example.com", 443)
        assert host_port_from_target("http://192.168.1.1:8080/bundle.js") == ("192.168.1.1", 8080)
        assert host_port_from_target("/local/path") == ("/local/path", 80)

    def test_parse_real_captured_trufflehog_stdout(self):
        parsed = parse_trufflehog_output(REAL_CAPTURED_TRUFFLEHOG_STDOUT)
        assert parsed["total_secrets"] == 1
        assert parsed["verified_count"] == 0
        assert parsed["unverified_count"] == 1
        assert parsed["by_detector"] == {"Slack": 1}

        secret = parsed["secrets"][0]
        assert secret["detector"] == "Slack"
        assert "Slack tokens" in secret["description"]
        assert secret["verified"] is False
        assert secret["line"] == 1
        assert secret["raw_secret"] == "xoxb-EXAMPLE00-EXAMPLE000000-EXAMPLEFAKETOKENFAKETOKENFAKETOKEN0"
        assert secret["masked_secret"] == "xoxb-E...KEN0"

    def test_parse_empty_and_noise(self):
        parsed = parse_trufflehog_output("")
        assert parsed["total_secrets"] == 0
        assert parsed["secrets"] == []
        assert parsed["aspnet_machinekey"] is None

        parsed_noise = parse_trufflehog_output("plain text without json")
        assert parsed_noise["total_secrets"] == 0
        assert parsed_noise["secrets"] == []
        assert parsed_noise["aspnet_machinekey"] is None

    def test_parse_real_captured_aspnet_machinekey_stdout(self):
        """Confirms both real-binary behaviors the docs got wrong/unclear
        on: DetectorName is literally "CustomRegex" for every hit (never
        the detector's own `name`), and each of the four single-regex
        detectors surfaces its own distinct value rather than one
        concatenated string."""
        parsed = parse_trufflehog_output(REAL_CAPTURED_ASPNET_MACHINEKEY_STDOUT)

        assert parsed["total_secrets"] == 4
        assert parsed["by_detector"] == {
            "ASPNETValidationAlgorithm": 1,
            "ASPNETDecryptionKey": 1,
            "ASPNETDecryptionAlgorithm": 1,
            "ASPNETValidationKey": 1,
        }

        # The display name resolved from ExtraData.name, not the raw
        # (always "CustomRegex") DetectorName.
        detectors = {s["detector"] for s in parsed["secrets"]}
        assert detectors == {
            "ASPNETValidationAlgorithm",
            "ASPNETDecryptionKey",
            "ASPNETDecryptionAlgorithm",
            "ASPNETValidationKey",
        }
        assert "CustomRegex" not in detectors

        assert parsed["aspnet_machinekey"] == {
            "validation_algorithm": "HMACSHA256",
            "decryption_key": "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210",
            "decryption_algorithm": "AES",
            "validation_key": "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6",
            "file": "/tmp/aspnet_test/web.config",
        }

    def test_parse_distinguishes_custom_regex_from_a_future_unrelated_custom_detector(self):
        """A custom-regex detector that isn't one of ours still gets a
        real display name from ExtraData.name (not folded into our
        aspnet_machinekey dict) -- the resolution logic is generic, not
        hardcoded to only recognize our four names."""
        line = (
            '{"SourceMetadata":{"Data":{"Filesystem":{"file":"f.txt","line":1}}},'
            '"DetectorName":"CustomRegex","DetectorDescription":"","DecoderName":"PLAIN",'
            '"Verified":false,"Raw":"somevalue","ExtraData":{"name":"SomeOtherDetector"}}'
        )
        parsed = parse_trufflehog_output(line)
        assert parsed["secrets"][0]["detector"] == "SomeOtherDetector"
        assert parsed["aspnet_machinekey"] is None
