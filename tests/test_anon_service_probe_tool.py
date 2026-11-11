"""
Unit tests for AnonServiceProbe tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.anon_service_probe.execute import AnonServiceResult, FtpResult, MySqlResult
from tradecraft.tools.anon_service_probe import AnonServiceProbe


def test_anon_service_probe_run():
    tool = AnonServiceProbe()
    fake_ftp = FtpResult(
        host="203.0.113.41",
        port=21,
        connected=True,
        banner="220 FTP Server ready.",
        anonymous_login=False,
        vulnerable=False,
        status="access_denied",
    )
    fake_mysql = MySqlResult(
        host="203.0.113.41",
        port=3306,
        connected=True,
        server_version="11.8.9-MariaDB-log",
        empty_root_password=False,
        vulnerable=False,
        status="access_denied",
    )
    fake_res = AnonServiceResult(
        target="203.0.113.41",
        host="203.0.113.41",
        ftp=fake_ftp,
        mysql=fake_mysql,
        vulnerable=False,
        summary="FTP: access_denied; MySQL: access_denied",
    )

    with patch("tradecraft.tools.anon_service_probe.anon_execute", return_value=fake_res):
        out = tool.run("203.0.113.41")
        assert out["vulnerable"] is False
        assert out["host"] == "203.0.113.41"
        assert "_full_evidence" in out


def test_anon_service_probe_extract_evidence():
    tool = AnonServiceProbe()
    fake_full = {"vulnerable": False, "summary": "clean"}
    result_dict = {"_full_evidence": fake_full, "host": "203.0.113.41"}

    ev = tool.extract_evidence({"target": "203.0.113.41"}, result_dict)
    assert ev is not None
    assert ev[0] == "203.0.113.41"
    assert ev[1] == fake_full
    assert "_full_evidence" not in result_dict


def test_anon_service_probe_extract_facts():
    tool = AnonServiceProbe()

    # Vulnerable FTP and clean MySQL
    res = {
        "host": "203.0.113.41",
        "vulnerable": True,
        "ftp": {"connected": True, "port": 21, "anonymous_login": True},
        "mysql": {"connected": True, "port": 3306, "server_version": "11.8.9", "empty_root_password": False},
    }
    facts = tool.extract_facts({"target": "203.0.113.41"}, res)
    assert len(facts) == 2

    ftp_fact = [f for f in facts if f["service"] == "ftp"][0]
    assert ftp_fact["severity"] == "high"
    assert "Anonymous Login" in ftp_fact["vulnerability"]

    mysql_fact = [f for f in facts if f["service"] == "mysql"][0]
    assert mysql_fact["state"] == "open"
    assert mysql_fact["version"] == "11.8.9"
    assert "vulnerability" not in mysql_fact
