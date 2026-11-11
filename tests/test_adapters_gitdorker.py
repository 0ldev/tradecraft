import csv
import io
from unittest.mock import MagicMock, patch

from tradecraft.adapters.gitdorker.execute import RawGitdorkerResult, execute
from tradecraft.adapters.gitdorker.parse import parse_findings


def _csv_to_rows(csv_text: str):
    reader = csv.reader(io.StringIO(csv_text))
    return [row for row in reader if row]


def test_repo_urls_are_parsed_and_deduplicated():
    csv_text = (
        "URL,Matched Dork\n"
        "https://github.com/acme/widgets,filename:config.json\n"
        "https://github.com/acme/widgets,filename:config.json\n"
        "https://github.com/acme/other,extension:pem\n"
    )
    rows = _csv_to_rows(csv_text)
    findings = parse_findings(rows)
    urls = [f["url"] for f in findings]
    assert urls == ["https://github.com/acme/widgets", "https://github.com/acme/other"]
    assert findings[0]["type"] == "repo"
    assert findings[0]["dork"] == "filename:config.json"


def test_password_and_secret_dorks_are_classified_as_secret_type():
    csv_text = (
        "URL,Matched Dork\n"
        "https://github.com/acme/leak,filename:.env password\n"
        "https://github.com/acme/creds,content:api_key\n"
        "https://github.com/acme/keys,extension:private_key\n"
    )
    rows = _csv_to_rows(csv_text)
    findings = parse_findings(rows)
    assert len(findings) == 3
    assert all(f["type"] == "secret" for f in findings)


def test_header_row_and_non_url_junk_are_skipped():
    csv_text = (
        "URL,Matched Dork\n"
        "\n"
        "not-a-url,junk\n"
        "https://github.com/acme/real,filename:.env\n"
    )
    rows = _csv_to_rows(csv_text)
    findings = parse_findings(rows)
    assert len(findings) == 1
    assert findings[0]["url"] == "https://github.com/acme/real"


def test_execute_missing_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    res = execute("exampleauto")
    assert res.error == "GITHUB_TOKEN environment variable not set"


def test_execute_missing_script(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "mock_token")
    with patch("os.path.isfile", return_value=False):
        res = execute("exampleauto")
        assert "GitDorker not found" in res.error


def test_execute_success(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "mock_token")
    mock_proc = MagicMock(returncode=0)

    with patch("os.path.isfile", return_value=True), \
         patch("subprocess.run", return_value=mock_proc), \
         patch("os.path.exists", return_value=True), \
         patch("os.path.getsize", return_value=100), \
         patch("builtins.open", unittest_mock_open("URL,Matched Dork\nhttps://github.com/target/repo,dork")):
        res = execute("exampleauto")
        assert res.error is None
        assert len(res.csv_rows) >= 1


def unittest_mock_open(content):
    from unittest.mock import mock_open
    return mock_open(read_data=content)
