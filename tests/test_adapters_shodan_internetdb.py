from unittest.mock import MagicMock, patch
import requests

from tradecraft.adapters.shodan_internetdb import execute as shodan_execute
from tradecraft.adapters.shodan_internetdb import parse as shodan_parse
from tradecraft.adapters.shodan_internetdb.execute import RawShodanResult


def test_normalize_ips():
    input_str = " 1.1.1.1, 8.8.8.8, 1.1.1.1 , not-an-ip, 2606:4700:4700::1111,  "
    res = shodan_execute.normalize_ips(input_str)
    assert res == ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"]
    assert shodan_execute.normalize_ips("invalid") == []
    assert shodan_execute.normalize_ips("") == []


def test_query_one_200_success():
    fake_data = {
        "ip": "1.1.1.1",
        "ports": [80, 443],
        "hostnames": ["one.one.one.one"],
        "cpes": [],
        "vulns": ["CVE-2020-1234"],
        "tags": ["cloud"],
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_data

    with patch("requests.get", return_value=mock_resp):
        res = shodan_execute.query_one("1.1.1.1")
        assert res.ip == "1.1.1.1"
        assert res.found is True
        assert res.body == fake_data
        assert res.error is None


def test_query_one_404_not_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("requests.get", return_value=mock_resp):
        res = shodan_execute.query_one("10.0.0.1")
        assert res.ip == "10.0.0.1"
        assert res.found is False
        assert res.body is None
        assert res.error is None


def test_query_one_http_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"

    with patch("requests.get", return_value=mock_resp):
        res = shodan_execute.query_one("1.1.1.1")
        assert res.ip == "1.1.1.1"
        assert res.found is False
        assert "HTTP 500" in res.error


def test_query_one_request_exception():
    with patch("requests.get", side_effect=requests.ConnectionError("Connection failed")):
        res = shodan_execute.query_one("1.1.1.1")
        assert res.ip == "1.1.1.1"
        assert res.found is False
        assert "Connection failed" in res.error


def test_execute_multiple_ips():
    with patch("tradecraft.adapters.shodan_internetdb.execute.query_one") as mock_q, \
         patch("time.sleep") as mock_sleep:
        mock_q.side_effect = [
            RawShodanResult(ip="1.1.1.1", found=True, body={"ports": [53]}),
            RawShodanResult(ip="8.8.8.8", found=False),
        ]
        results = shodan_execute.execute("1.1.1.1, 8.8.8.8")
        assert len(results) == 2
        assert results[0].found is True
        assert results[1].found is False
        mock_sleep.assert_called_once_with(0.2)


def test_execute_empty_ip():
    results = shodan_execute.execute("invalid, also-invalid")
    assert len(results) == 1
    assert "no valid IP" in results[0].error


def test_parse_one():
    # Error case
    res_err = RawShodanResult(ip="1.1.1.1", error="boom")
    assert shodan_parse.parse_one(res_err) == {"ip": "1.1.1.1", "error": "boom"}

    # Not found case
    res_not_found = RawShodanResult(ip="1.1.1.1", found=False)
    assert shodan_parse.parse_one(res_not_found) == {"ip": "1.1.1.1", "known_to_shodan": False}

    # Found case
    res_found = RawShodanResult(
        ip="1.1.1.1",
        found=True,
        body={
            "ports": [80, 443],
            "hostnames": ["one.one.one.one"],
            "cpes": ["cpe:/a:cloudflare"],
            "vulns": ["CVE-2021-9999"],
            "tags": ["dns"],
        },
    )
    parsed = shodan_parse.parse_one(res_found)
    assert parsed["known_to_shodan"] is True
    assert parsed["ports"] == [80, 443]
    assert parsed["hostnames"] == ["one.one.one.one"]
    assert parsed["vulns"] == ["CVE-2021-9999"]
    assert parsed["tags"] == ["dns"]


def test_parse_all():
    raw_list = [
        RawShodanResult(ip="1.1.1.1", found=True, body={"ports": [80]}),
        RawShodanResult(ip="8.8.8.8", found=False),
    ]
    all_parsed = shodan_parse.parse_all(raw_list)
    assert len(all_parsed) == 2
    assert all_parsed[0]["known_to_shodan"] is True
    assert all_parsed[1]["known_to_shodan"] is False
