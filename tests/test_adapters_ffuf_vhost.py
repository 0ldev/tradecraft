import json
from unittest.mock import MagicMock, patch

from tradecraft.adapters.ffuf.execute import CanarySignature
from tradecraft.adapters.ffuf_vhost.execute import (
    build_argv,
    execute,
    normalize_target,
    probe_vhost_baseline,
)
from tradecraft.adapters.ffuf_vhost.parse import parse_vhosts


def test_normalize_target():
    base, host, port = normalize_target("example.com")
    assert base == "https://example.com/"
    assert host == "example.com"
    assert port == 443

    base, host, port = normalize_target("http://target.local:8080/path")
    assert base == "http://target.local:8080/"
    assert host == "target.local"
    assert port == 8080

    base, host, port = normalize_target("http://plain.com")
    assert base == "http://plain.com/"
    assert host == "plain.com"
    assert port == 80


def test_build_argv():
    argv = build_argv("https://target.com/", "target.com", "/path/to/wordlist.txt", "/tmp/out.json")
    assert argv == [
        "ffuf",
        "-u", "https://target.com/",
        "-w", "/path/to/wordlist.txt",
        "-H", "Host: FUZZ.target.com",
        "-mc", "200,204,301,302,307,308,401,403,500",
        "-ac",
        "-of", "json",
        "-o", "/tmp/out.json",
        "-s",
    ]


@patch("requests.get")
def test_probe_vhost_baseline_success(mock_get):
    resp = MagicMock()
    resp.status_code = 200
    resp.content = b"welcome to default vhost"
    resp.headers = {}
    mock_get.return_value = resp

    baseline = probe_vhost_baseline("https://target.com/", "target.com")
    assert baseline is not None
    assert baseline.status_code == 200
    assert baseline.length == len(b"welcome to default vhost")


@patch("requests.get")
def test_probe_vhost_baseline_failure(mock_get):
    mock_get.side_effect = Exception("network down")
    baseline = probe_vhost_baseline("https://target.com/", "target.com")
    assert baseline is None


def test_parse_vhosts_filtering_and_dedup():
    raw_results = {
        "results": [
            {"input": {"FUZZ": "admin"}, "status": 200, "length": 500},
            {"input": {"FUZZ": "default"}, "status": 404, "length": 120},  # matches baseline
            {"input": {"FUZZ": "api"}, "status": 200, "length": 450},
            {"input": {"FUZZ": "ADMIN"}, "status": 200, "length": 500},  # duplicate
        ]
    }
    baseline = CanarySignature(status_code=404, length=120)
    vhosts = parse_vhosts(json.dumps(raw_results), baseline, "example.com")

    assert len(vhosts) == 2
    assert vhosts[0] == {"vhost": "admin.example.com", "status_code": 200}
    assert vhosts[1] == {"vhost": "api.example.com", "status_code": 200}


def test_parse_vhosts_empty():
    assert parse_vhosts("", None, "example.com") == []
    assert parse_vhosts("not json", None, "example.com") == []
    assert parse_vhosts("{}", None, "example.com") == []


@patch("tradecraft.adapters.ffuf_vhost.execute.resolve_wordlist")
def test_execute_missing_wordlist(mock_resolve):
    mock_resolve.return_value = "/nonexistent/wordlist.txt"
    res = execute("example.com")
    assert res.error is not None
    assert "Wordlist not found" in res.error


@patch("subprocess.run")
@patch("tradecraft.adapters.ffuf_vhost.execute.probe_vhost_baseline")
@patch("tradecraft.adapters.ffuf_vhost.execute.resolve_wordlist")
def test_execute_success(mock_resolve, mock_probe, mock_run, tmp_path):
    wl = tmp_path / "vhosts.txt"
    wl.write_text("admin\napi\n")
    mock_resolve.return_value = str(wl)

    mock_probe.return_value = CanarySignature(status_code=404, length=100)

    sample_output = json.dumps({
        "results": [
            {"input": {"FUZZ": "admin"}, "status": 200, "length": 250}
        ]
    })

    def fake_run(cmd, **kwargs):
        out_file = cmd[cmd.index("-o") + 1]
        with open(out_file, "w") as f:
            f.write(sample_output)
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run.side_effect = fake_run

    res = execute("https://example.com")
    assert res.error is None
    assert res.returncode == 0
    assert "admin" in res.json_output
    assert res.baseline == CanarySignature(status_code=404, length=100)
