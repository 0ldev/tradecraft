import json
from unittest.mock import MagicMock, patch

from tradecraft.adapters.clairvoyance.execute import (
    execute,
    find_script,
    normalize_target_url,
)
from tradecraft.adapters.clairvoyance.parse import parse_schema


def test_normalize_target_url():
    assert normalize_target_url("example.com/graphql") == "https://example.com/graphql"
    assert normalize_target_url("http://api.local/graphql") == "http://api.local/graphql"
    assert normalize_target_url("") == ""


@patch("os.path.isfile")
def test_find_script(mock_isfile):
    mock_isfile.side_effect = lambda path: path == "/opt/clairvoyance/clairvoyance.py"
    assert find_script() == "/opt/clairvoyance/clairvoyance.py"


@patch("tradecraft.adapters.clairvoyance.execute.find_script")
def test_execute_missing_script(mock_find):
    mock_find.return_value = None
    res = execute("https://api.example.com/graphql")
    assert res.error is not None
    assert "clairvoyance not found" in res.error


@patch("subprocess.run")
@patch("tradecraft.adapters.clairvoyance.execute.find_script")
def test_execute_success(mock_find, mock_run):
    mock_find.return_value = "/opt/clairvoyance/clairvoyance.py"

    sample_json = json.dumps({
        "queryType": {"fields": [{"name": "getUser"}, {"name": "listItems"}]},
        "mutationType": {"fields": [{"name": "createItem"}]},
    })

    def fake_run(cmd, **kwargs):
        out_file = cmd[cmd.index("-o") + 1]
        with open(out_file, "w") as f:
            f.write(sample_json)
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run.side_effect = fake_run

    res = execute("api.example.com/graphql")
    assert res.error is None
    assert res.returncode == 0
    assert "getUser" in res.json_output
    assert res.target_url == "https://api.example.com/graphql"


def test_parse_schema_direct_format():
    sample = {
        "queryType": {"fields": [{"name": "getUser"}, {"name": "listItems"}]},
        "mutationType": {"fields": [{"name": "createItem"}]},
    }
    parsed = parse_schema(json.dumps(sample))
    assert parsed["schema_recovered"] is True
    assert parsed["queries"] == ["getUser", "listItems"]
    assert parsed["mutations"] == ["createItem"]


def test_parse_schema_graphql_schema_format():
    sample = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {
                        "name": "Query",
                        "fields": [{"name": "userById"}, {"name": "allProducts"}],
                    },
                    {
                        "name": "Mutation",
                        "fields": [{"name": "deleteUser"}],
                    },
                ],
            }
        }
    }
    parsed = parse_schema(json.dumps(sample))
    assert parsed["schema_recovered"] is True
    assert parsed["queries"] == ["userById", "allProducts"]
    assert parsed["mutations"] == ["deleteUser"]


def test_parse_schema_empty_and_unexpected():
    assert parse_schema("") == {
        "schema_recovered": False,
        "queries": [],
        "mutations": [],
    }
    res = parse_schema("not json")
    assert res["schema_recovered"] is True
    assert "unexpected" in res.get("note", "")

    res_empty_dict = parse_schema("{}")
    assert res_empty_dict["schema_recovered"] is True
    assert "unexpected" in res_empty_dict.get("note", "")
