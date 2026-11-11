"""Unit tests for cloudenum adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.cloudenum.execute import (
    RawCloudEnumResult,
    build_argv,
    derive_keyword,
    execute,
    registrable_domain,
)
from tradecraft.adapters.cloudenum.parse import host_port_from_target, parse_cloudenum_output

REAL_CAPTURED_CLOUDENUM_JSON = """#### CLOUD_ENUM 01/11/2026 19:24:49 ####
{"platform": "aws", "msg": "Protected S3 Bucket", "target": "http://testtest123.s3.amazonaws.com/", "access": "protected"}
{"platform": "aws", "msg": "AWS App Found:", "target": "https://testtest123.awsapps.com", "access": "protected"}
{"platform": "azure", "msg": "Disabled Account", "target": "http://testtest123.blob.core.windows.net/", "access": "disabled"}
{"platform": "azure", "msg": "Disabled Account", "target": "http://testtest123.file.core.windows.net/", "access": "disabled"}
{"platform": "azure", "msg": "Disabled Account", "target": "http://testtest123.queue.core.windows.net/", "access": "disabled"}
{"platform": "azure", "msg": "Disabled Account", "target": "http://testtest123.table.core.windows.net/", "access": "disabled"}
{"platform": "azure", "msg": "Registered Azure Database DNS Name", "target": "testtest123.database.windows.net", "access": "public"}
{"platform": "gcp", "msg": "Protected Google Bucket", "target": "http://storage.googleapis.com/testtest123", "access": "protected"}
"""


class TestCloudEnumExecute:
    def test_registrable_domain(self):
        assert registrable_domain("www.examplepaint.com.br") == "examplepaint.com.br"
        assert registrable_domain("materiais.examplepaint.com.br") == "examplepaint.com.br"
        assert registrable_domain("api.exampleauto.com.br") == "exampleauto.com.br"
        assert registrable_domain("sub.example.co.uk") == "example.co.uk"
        assert registrable_domain("example.com") == "example.com"
        assert registrable_domain("barehostname") is None

    def test_derive_keyword(self):
        # All subdomains of the same registrable domain must collapse to the identical company keyword
        assert derive_keyword("examplepaint.com.br") == "examplepaint"
        assert derive_keyword("www.examplepaint.com.br") == "examplepaint"
        assert derive_keyword("mail.examplepaint.com.br") == "examplepaint"
        assert derive_keyword("https://exampleauto.com.br:8443/app") == "exampleauto"
        assert derive_keyword("exampleauto") == "exampleauto"
        assert derive_keyword("") == ""

    def test_build_argv_default(self):
        argv = build_argv("examplepaint")
        assert argv == [
            "cloud_enum",
            "-k", "examplepaint",
            "-f", "json",
            "-qs",
        ]

    def test_build_argv_custom(self):
        argv = build_argv(
            "exampleauto",
            quickscan=False,
            disable_aws=True,
            disable_azure=False,
            disable_gcp=True,
            threads=10,
            output_file="/tmp/cloud.json",
        )
        assert argv == [
            "cloud_enum",
            "-k", "exampleauto",
            "-f", "json",
            "-l", "/tmp/cloud.json",
            "--disable-aws",
            "--disable-gcp",
            "-t", "10",
        ]

    def test_execute_invalid_target(self):
        res = execute("???")
        assert "Cannot derive a valid company keyword" in (res.error or "")

    @patch("shutil.which", return_value=None)
    def test_execute_missing_binary(self, mock_which):
        res = execute("examplepaint.com.br")
        assert "cloud_enum binary not found on PATH" in (res.error or "")

    @patch("shutil.which", return_value="/usr/local/bin/cloud_enum")
    @patch("subprocess.run")
    def test_execute_success(self, mock_run, mock_which):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "All done, happy hacking!"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        with patch("builtins.open", MagicMock()) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = REAL_CAPTURED_CLOUDENUM_JSON
            with patch("os.path.exists", return_value=True):
                res = execute("examplepaint.com.br")
                assert res.error is None
                assert res.keyword == "examplepaint"
                assert res.json_content == REAL_CAPTURED_CLOUDENUM_JSON

    @patch("shutil.which", return_value="/usr/local/bin/cloud_enum")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="cloud_enum", timeout=60))
    def test_execute_timeout(self, mock_run, mock_which):
        res = execute("examplepaint.com.br", subprocess_timeout=60)
        assert "timed out after 60s" in (res.error or "")


class TestCloudEnumParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("https://example.com/test") == ("example.com", 443)
        assert host_port_from_target("sub.example.com") == ("sub.example.com", 443)
        assert host_port_from_target("keyword") == ("keyword", 443)

    def test_parse_real_captured_cloudenum_json(self):
        parsed = parse_cloudenum_output(json_content=REAL_CAPTURED_CLOUDENUM_JSON)
        assert parsed["total_resources"] == 8
        assert parsed["public_count"] == 1
        assert parsed["protected_count"] == 3
        assert parsed["disabled_count"] == 4
        assert parsed["by_platform"] == {"aws": 2, "azure": 5, "gcp": 1}

        # Verify items
        db_item = next(r for r in parsed["resources"] if r["platform"] == "azure" and r["is_public"])
        assert db_item["resource"] == "testtest123.database.windows.net"
        assert db_item["is_public"] is True

        aws_item = next(r for r in parsed["resources"] if r["platform"] == "aws")
        assert "http://testtest123.s3.amazonaws.com/" in aws_item["resource"]
        assert aws_item["is_public"] is False
        assert aws_item["access"] == "protected"

    def test_parse_empty_and_noise(self):
        parsed = parse_cloudenum_output(json_content="", stdout="No items found")
        assert parsed["total_resources"] == 0
        assert parsed["public_count"] == 0
        assert parsed["resources"] == []
