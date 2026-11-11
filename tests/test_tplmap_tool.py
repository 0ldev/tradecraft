from unittest.mock import patch

from tradecraft.adapters.tplmap.execute import RawTplmapResult
from tradecraft.tools.tplmap import Tplmap


def test_tplmap_availability():
    tool = Tplmap()
    with patch("tradecraft.tools.tplmap.tplmap_find_script", return_value=None):
        assert tool.is_available() is False
    with patch("tradecraft.tools.tplmap.tplmap_find_script", return_value="/opt/tplmap/tplmap.py"):
        with patch.object(Tplmap, "is_available", return_value=True):
            assert tool.is_available() is True


def test_tplmap_run_error():
    tool = Tplmap()
    with patch("tradecraft.tools.tplmap.tplmap_execute") as mock_exec:
        mock_exec.return_value = RawTplmapResult(error="Host unreachable")
        res = tool.run(target_url="http://example.com/test?q=1")
        assert res["target"] == "http://example.com/test?q=1"
        assert res["target_url"] == "http://example.com/test?q=1"
        assert res["error"] == "Host unreachable"


def test_tplmap_run_vulnerable():
    tool = Tplmap()
    vulnerable_stdout = """
[+] Jinja2 plugin has confirmed injection with tag '*' 
[+] SSTImap identified the following injection point:

  Query parameter: q
  Engine: Jinja2
  Injection: *
  Technique: rendered
"""
    with patch("tradecraft.tools.tplmap.tplmap_execute") as mock_exec:
        mock_exec.return_value = RawTplmapResult(stdout=vulnerable_stdout)
        res = tool.run(target_url="http://example.com:8080/greet?q=test")

        assert res["target"] == "http://example.com:8080/greet?q=test"
        assert res["target_url"] == "http://example.com:8080/greet?q=test"
        assert res["vulnerable"] is True
        assert res["engine"] == "Jinja2"
        assert res["parameter"] == "q"

        facts = tool.extract_facts({"target_url": "http://example.com:8080/greet?q=test"}, res)
        assert len(facts) == 1
        assert facts[0]["host"] == "example.com"
        assert facts[0]["port"] == 8080
        assert facts[0]["vulnerability"] == "Server-Side Template Injection (SSTI)"
        assert facts[0]["severity"] == "high"
        assert facts[0]["template_engine"] == "Jinja2"

        evidence = tool.extract_evidence({"target_url": "http://example.com:8080/greet?q=test"}, res)
        assert evidence is not None
        assert evidence[0] == "http://example.com:8080/greet?q=test"


def test_tplmap_run_not_vulnerable():
    tool = Tplmap()
    clean_stdout = "[-] Tested parameters appear to be not injectable."
    with patch("tradecraft.tools.tplmap.tplmap_execute") as mock_exec:
        mock_exec.return_value = RawTplmapResult(stdout=clean_stdout)
        res = tool.run(target_url="http://example.com/greet?q=test")

        assert res["vulnerable"] is False
        facts = tool.extract_facts({"target_url": "http://example.com/greet?q=test"}, res)
        assert facts == []
