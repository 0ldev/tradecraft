from unittest.mock import patch

from tradecraft.adapters.clairvoyance.execute import RawClairvoyanceResult
from tradecraft.tools.clairvoyance import Clairvoyance


def test_clairvoyance_is_available():
    tool = Clairvoyance()
    with patch("shutil.which") as mock_which, patch("tradecraft.adapters.clairvoyance.execute.find_script") as mock_find:
        mock_which.return_value = "/usr/bin/python3"
        mock_find.return_value = "/opt/clairvoyance/clairvoyance.py"
        assert tool.is_available() is True

        mock_find.return_value = None
        assert tool.is_available() is False


def test_clairvoyance_run_error():
    tool = Clairvoyance()
    with patch("tradecraft.adapters.clairvoyance.execute.execute") as mock_exec:
        mock_exec.return_value = RawClairvoyanceResult(error="clairvoyance not found")
        res = tool.run("https://api.example.com/graphql")
        assert res["target"] == "https://api.example.com/graphql"
        assert res["schema_recovered"] is False
        assert res["queries"] == []
        assert res["mutations"] == []
        assert res["error"] == "clairvoyance not found"


def test_clairvoyance_run_success():
    tool = Clairvoyance()
    sample_json = '{"queryType": {"fields": [{"name": "viewer"}]}}'
    with patch("tradecraft.adapters.clairvoyance.execute.execute") as mock_exec:
        mock_exec.return_value = RawClairvoyanceResult(
            json_output=sample_json,
            returncode=0,
            target_url="https://api.example.com/graphql",
        )
        res = tool.run("https://api.example.com/graphql")
        assert res["target"] == "https://api.example.com/graphql"
        assert res["schema_recovered"] is True
        assert res["queries"] == ["viewer"]
        assert "_full_evidence" in res


def test_clairvoyance_extract_evidence():
    tool = Clairvoyance()
    res = {
        "target": "https://api.example.com/graphql",
        "schema_recovered": True,
        "queries": ["viewer"],
        "mutations": [],
        "_full_evidence": {
            "target": "https://api.example.com/graphql",
            "raw_schema": "{}",
            "queries": ["viewer"],
            "mutations": [],
        },
    }
    host, evidence = tool.extract_evidence({"target": "https://api.example.com/graphql"}, res)
    assert host == "api.example.com"
    assert evidence["queries"] == ["viewer"]
    assert "_full_evidence" not in res


def test_clairvoyance_extract_facts():
    tool = Clairvoyance()
    res = {
        "target": "https://api.example.com:8443/graphql",
        "schema_recovered": True,
        "queries": ["viewer", "users"],
        "mutations": ["updateUser"],
        "evidence_id": "ev_gql",
    }
    facts = tool.extract_facts({"target": "https://api.example.com:8443/graphql"}, res)
    assert len(facts) == 1
    assert facts[0] == {
        "host": "api.example.com",
        "port": 8443,
        "graphql_schema_recovered_without_introspection": "2 queries, 1 mutations",
        "evidence": "ev_gql",
    }
