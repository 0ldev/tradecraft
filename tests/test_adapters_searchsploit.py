"""Unit tests for searchsploit adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.searchsploit.execute import (
    RawSearchsploitResult,
    build_argv,
    execute,
)
from tradecraft.adapters.searchsploit.parse import (
    host_port_from_target,
    parse_searchsploit_output,
)

REAL_CAPTURED_SEARCH_JSON = """
{
	"SEARCH": "Apache 2.4.49",
	"DB_PATH_EXPLOIT": "/opt/exploitdb",
	"RESULTS_EXPLOIT": [
		{"Title":"Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)","EDB-ID":"50383","Date_Published":"2021-10-06","Date_Added":"2021-10-06","Date_Updated":"2022-02-11","Author":"Lucas Souza","Type":"webapps","Platform":"multiple","Port":"","Verified":"1","Codes":"CVE-2021-41773","Tags":"","Aliases":"","Screenshot":"","Application":"http://www.exploit-db.comhttpd-2.4.49.tar.gz","Source":"","Path":"/opt/exploitdb/exploits/multiple/webapps/50383.sh"},
		{"Title":"Apache HTTP Server 2.4.50 - Remote Code Execution (RCE) (3)","EDB-ID":"50512","Date_Published":"2021-11-11","Date_Added":"2021-11-11","Date_Updated":"2022-04-19","Author":"Valentin Lobstein","Type":"webapps","Platform":"multiple","Port":"","Verified":"1","Codes":"CVE-2021-42013;CVE-2021-41773","Tags":"","Aliases":"","Screenshot":"","Application":"","Source":"","Path":"/opt/exploitdb/exploits/multiple/webapps/50512.py"}
	],
	"DB_PATH_SHELLCODE": "/opt/exploitdb",
	"RESULTS_SHELLCODE": [	]
}
"""

REAL_CAPTURED_EMPTY_JSON = """
{
	"SEARCH": "nonexistent_term",
	"DB_PATH_EXPLOIT": "/opt/exploitdb",
	"RESULTS_EXPLOIT": [	],
	"DB_PATH_SHELLCODE": "/opt/exploitdb",
	"RESULTS_SHELLCODE": [	]
}
"""

REAL_CAPTURED_EXAMINE_STDOUT = """
  Exploit: Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)
      URL: https://www.exploit-db.com/exploits/50383
     Path: /opt/exploitdb/exploits/multiple/webapps/50383.sh
    Codes: CVE-2021-41773
 Verified: True
File Type: ASCII text
"""

SAMPLE_POC_CONTENT = """#!/bin/bash
# CVE-2021-41773
curl -s --path-as-is "$host/cgi-bin/.%2e/%2e%2e/etc/passwd"
"""


class TestSearchsploitExecute:
    def test_build_argv_query(self):
        argv = build_argv(query="Apache 2.4.49")
        assert argv == ["searchsploit", "-j", "Apache", "2.4.49"]

    def test_build_argv_cve(self):
        argv1 = build_argv(cve="CVE-2021-41773")
        assert argv1 == ["searchsploit", "-j", "--cve", "2021-41773"]
        argv2 = build_argv(cve="2021-41773")
        assert argv2 == ["searchsploit", "-j", "--cve", "2021-41773"]

    def test_build_argv_edb_id(self):
        argv = build_argv(edb_id="50383")
        assert argv == ["searchsploit", "-p", "50383"]

    def test_execute_empty_args(self):
        res = execute()
        assert res.error == "at least one of 'query', 'cve', or 'edb_id' must be specified"

    @patch("tradecraft.adapters.searchsploit.execute.shutil.which", return_value=None)
    def test_execute_missing_binary(self, mock_which):
        res = execute(query="Apache")
        assert "searchsploit binary not found" in (res.error or "")

    @patch("tradecraft.adapters.searchsploit.execute.shutil.which", return_value="/usr/bin/searchsploit")
    @patch("tradecraft.adapters.searchsploit.execute.subprocess.run")
    def test_execute_success_search(self, mock_run, mock_which):
        mock_proc = MagicMock()
        mock_proc.stdout = REAL_CAPTURED_SEARCH_JSON
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = execute(query="Apache 2.4.49")
        assert res.error is None
        assert res.returncode == 0
        assert "50383" in res.stdout

    @patch("tradecraft.adapters.searchsploit.execute.shutil.which", return_value="/usr/bin/searchsploit")
    @patch("tradecraft.adapters.searchsploit.execute.subprocess.run")
    def test_execute_timeout(self, mock_run, mock_which):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["searchsploit"], timeout=30)
        res = execute(query="Apache", timeout=30)
        assert "searchsploit timed out after 30s" in (res.error or "")

    @patch("tradecraft.adapters.searchsploit.execute.shutil.which", return_value="/usr/bin/searchsploit")
    @patch("tradecraft.adapters.searchsploit.execute.os.path.isfile", return_value=True)
    @patch("builtins.open", new_callable=MagicMock)
    @patch("tradecraft.adapters.searchsploit.execute.subprocess.run")
    def test_execute_examine_edb_id(self, mock_run, mock_open, mock_isfile, mock_which):
        mock_proc = MagicMock()
        mock_proc.stdout = REAL_CAPTURED_EXAMINE_STDOUT
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        mock_file = MagicMock()
        mock_file.read.return_value = SAMPLE_POC_CONTENT
        mock_open.return_value.__enter__.return_value = mock_file

        res = execute(edb_id="50383")
        assert res.edb_id == "50383"
        assert res.file_path == "/opt/exploitdb/exploits/multiple/webapps/50383.sh"
        assert "CVE-2021-41773" in res.file_content


class TestSearchsploitParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("http://example.com:8080") == ("example.com", 8080)
        assert host_port_from_target("https://example.com") == ("example.com", 443)
        assert host_port_from_target("example.com") == ("example.com", 80)

    def test_parse_empty(self):
        parsed = parse_searchsploit_output(REAL_CAPTURED_EMPTY_JSON, query="nonexistent")
        assert parsed["mode"] == "search"
        assert parsed["total_exploits"] == 0
        assert parsed["exploits"] == []

    def test_parse_real_captured_search(self):
        parsed = parse_searchsploit_output(REAL_CAPTURED_SEARCH_JSON, query="Apache 2.4.49")
        assert parsed["mode"] == "search"
        assert parsed["total_exploits"] == 2
        exp1 = parsed["exploits"][0]
        assert exp1["edb_id"] == "50383"
        assert "Path Traversal" in exp1["title"]
        assert exp1["type"] == "webapps"
        assert exp1["verified"] is True
        assert "CVE-2021-41773" in exp1["codes"]

        exp2 = parsed["exploits"][1]
        assert exp2["edb_id"] == "50512"

    def test_parse_examine_mode(self):
        parsed = parse_searchsploit_output(
            stdout=REAL_CAPTURED_EXAMINE_STDOUT,
            edb_id="50383",
            file_content=SAMPLE_POC_CONTENT,
            file_path="/opt/exploitdb/exploits/multiple/webapps/50383.sh",
        )
        assert parsed["mode"] == "examine"
        assert parsed["edb_id"] == "50383"
        assert "Apache HTTP Server" in parsed["title"]
        assert parsed["verified"] is True
        assert parsed["codes"] == "CVE-2021-41773"
        assert parsed["path"] == "/opt/exploitdb/exploits/multiple/webapps/50383.sh"
        assert "curl" in parsed["poc_content"]
