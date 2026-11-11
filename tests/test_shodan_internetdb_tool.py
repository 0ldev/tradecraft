from unittest.mock import patch

from tradecraft.adapters.shodan_internetdb.execute import RawShodanResult
from tradecraft.tools.shodan_internetdb import ShodanInternetdb


def test_shodan_internetdb_tool_run():
    tool = ShodanInternetdb()
    with patch("tradecraft.tools.shodan_internetdb.shodan_execute.execute") as mock_exec:
        mock_exec.return_value = [
            RawShodanResult(
                ip="1.1.1.1",
                found=True,
                body={
                    "ports": [80, 443],
                    "hostnames": ["one.one.one.one"],
                    "cpes": [],
                    "vulns": ["CVE-2020-0001"],
                    "tags": [],
                },
            ),
            RawShodanResult(ip="8.8.8.8", found=False),
        ]
        res = tool.run("1.1.1.1, 8.8.8.8")
        assert res["ip"] == "1.1.1.1, 8.8.8.8"
        assert res["total_queried"] == 2
        assert len(res["results"]) == 2
        assert res["results"][0]["known_to_shodan"] is True
        assert res["results"][1]["known_to_shodan"] is False

        # Facts extraction: emits fact per port for known IPs only. hostnames/
        # vulns are host-level in Shodan InternetDB's schema, so they're
        # attached once (on the first port) rather than repeated on every
        # port -- a real run had the same 13-hostname list repeated across
        # 9 port rows for one IP in the generated report.
        facts = tool.extract_facts({"ip": "1.1.1.1, 8.8.8.8"}, res)
        assert len(facts) == 2
        assert facts[0] == {
            "host": "1.1.1.1",
            "port": 80,
            "shodan_vulns": "CVE-2020-0001",
            "shodan_hostnames": "one.one.one.one",
        }
        assert facts[1] == {
            "host": "1.1.1.1",
            "port": 443,
        }

        # Evidence extraction keys off first IP
        canonical, full, aliases = tool.extract_evidence({"ip": "1.1.1.1, 8.8.8.8"}, res)
        assert canonical == "1.1.1.1"
        assert len(full["results"]) == 2
        assert aliases == ["8.8.8.8"]


def test_shodan_internetdb_tool_extract_facts_with_evidence_id():
    tool = ShodanInternetdb()
    res = {
        "evidence_id": "shodan_internetdb:1.1.1.1",
        "results": [
            {
                "ip": "1.1.1.1",
                "known_to_shodan": True,
                "ports": [80],
                "vulns": [],
                "hostnames": [],
            }
        ],
    }
    facts = tool.extract_facts({"ip": "1.1.1.1"}, res)
    assert len(facts) == 1
    assert facts[0] == {
        "host": "1.1.1.1",
        "port": 80,
        "evidence": "shodan_internetdb:1.1.1.1",
    }


def test_shodan_internetdb_tool_extract_facts_empty_for_unknown():
    tool = ShodanInternetdb()
    res = {
        "results": [
            {"ip": "10.0.0.1", "known_to_shodan": False},
            {"ip": "10.0.0.2", "error": "timeout"},
        ]
    }
    facts = tool.extract_facts({"ip": "10.0.0.1, 10.0.0.2"}, res)
    assert facts == []
