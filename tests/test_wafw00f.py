import json
import subprocess
from unittest.mock import patch

from tradecraft.adapters.wafw00f import execute as wafw00f_execute
from tradecraft.adapters.wafw00f import parse as wafw00f_parse
from tradecraft.tools.wafw00f import Wafw00f


def _write_output_and_succeed(argv, **kwargs):
    out_path = argv[argv.index("-o") + 1]
    with open(out_path, "w") as f:
        json.dump([{"waf": "Cloudflare"}], f)
    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


def test_parse_wafs_dedupes_and_drops_none():
    json_output = json.dumps([{"waf": "Cloudflare"}, {"waf": "Cloudflare"}, {"waf": "None"}])
    assert wafw00f_parse.parse_wafs(json_output) == ["Cloudflare"]


def test_parse_wafs_empty_for_blank_output():
    assert wafw00f_parse.parse_wafs("") == []


def test_host_port_from_target():
    assert wafw00f_parse.host_port_from_target("10.0.0.5") == ("10.0.0.5", None)
    assert wafw00f_parse.host_port_from_target("10.0.0.5:8443") == ("10.0.0.5", 8443)


def test_execution_builds_json_output_file_and_cleans_up():
    with patch("subprocess.run", side_effect=_write_output_and_succeed):
        result = wafw00f_execute.execute("10.0.0.5", timeout=30)
    assert json.loads(result.json_output) == [{"waf": "Cloudflare"}]


def test_missing_binary_and_timeout_are_reported():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        assert wafw00f_execute.execute("10.0.0.5").error == "wafw00f executable not found"
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("wafw00f", 120)):
        assert wafw00f_execute.execute("10.0.0.5").error == "wafw00f timed out after 120s"


def test_run_returns_detected_wafs():
    with patch("subprocess.run", side_effect=_write_output_and_succeed):
        result = Wafw00f().run(target="10.0.0.5")
    assert result == {"target": "10.0.0.5", "wafs_detected": ["Cloudflare"]}


def test_extract_facts_merges_waf_onto_derived_host_port():
    tool = Wafw00f()
    facts = tool.extract_facts({"target": "10.0.0.5:8443"}, {"wafs_detected": ["Cloudflare"]})
    assert facts == [{"host": "10.0.0.5", "port": 8443, "waf": "Cloudflare"}]


def test_extract_facts_empty_when_no_waf_detected():
    tool = Wafw00f()
    assert tool.extract_facts({"target": "10.0.0.5"}, {"wafs_detected": []}) == []
