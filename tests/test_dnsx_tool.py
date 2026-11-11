"""Unit tests for Dnsx tool, evidence extraction, and facts extraction."""
from unittest.mock import MagicMock, patch

from tradecraft.adapters.dnsx.execute import RawDnsxResult
from tradecraft.tools.dnsx import Dnsx


class TestDnsxTool:
    @patch("tradecraft.tools.dnsx.dnsx_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawDnsxResult(error="dnsx executable not found")
        tool = Dnsx()
        res = tool.run(target="example.com")
        assert res["target"] == "example.com"
        assert res["records"] == []
        assert res["error"] == "dnsx executable not found"

    @patch("tradecraft.tools.dnsx.dnsx_execute.execute")
    @patch("tradecraft.tools.dnsx.dnsx_parse.parse_dns_records")
    def test_run_few_records(self, mock_parse, mock_exec):
        mock_exec.return_value = RawDnsxResult(stdout="{}", returncode=0)
        mock_parse.return_value = [
            {"host": "example.com", "resolves": True, "a": ["93.184.216.34"]}
        ]
        tool = Dnsx()
        res = tool.run(target="example.com")
        assert res["total_records"] == 1
        assert len(res["records"]) == 1
        assert "_full_evidence" in res
        assert "omitted_records" not in res

    @patch("tradecraft.tools.dnsx.dnsx_execute.execute")
    @patch("tradecraft.tools.dnsx.dnsx_parse.parse_dns_records")
    def test_run_omits_records_when_exceeding_10(self, mock_parse, mock_exec):
        mock_exec.return_value = RawDnsxResult(stdout="{}", returncode=0)
        mock_parse.return_value = [
            {"host": f"sub{i}.example.com", "resolves": True, "a": [f"1.1.1.{i}"]}
            for i in range(15)
        ]
        tool = Dnsx()
        res = tool.run(target="example.com")
        assert res["total_records"] == 15
        assert len(res["records"]) == 10
        assert res["omitted_records"] == 5
        assert "5 more records omitted" in res["note"]
        assert len(res["_full_evidence"]["records"]) == 15

    def test_extract_evidence(self):
        tool = Dnsx()
        result = {
            "target": "example.com,www.example.com",
            "records": [{"host": "example.com"}],
            "_full_evidence": {"records": [{"host": "example.com"}]},
        }
        ev = tool.extract_evidence({"target": "example.com,www.example.com"}, result)
        assert ev is not None
        target, data, aliases = ev
        # Should pick primary/first host
        assert target == "example.com"
        # The other batch member must be registered as an alias, or
        # read_evidence on it always reports "not found" -- see
        # EvidenceStore.save()'s docstring.
        assert aliases == ["www.example.com"]
        # Peeks, doesn't pop: extract_facts (called after this in the real
        # loop, tradecraft/execution/loop.py) still needs _full_evidence to
        # produce a fact for every record, not just the truncated display
        # subset. The loop itself strips the key before returning to the
        # model, once both extractions are done.
        assert "_full_evidence" in result

    def test_extract_facts_uses_full_evidence_to_cover_records_past_truncation(self):
        # Mirrors a real run_consecutive_scope.sh engagement: dnsx truncates
        # its displayed "records" to 10, but every resolved host still
        # needs its own fact row (with its own evidence pointer) or it's
        # silently invisible in Known Facts even though its full record is
        # sitting in the evidence store.
        tool = Dnsx()
        full_records = [
            {"host": f"sub{i}.example.com", "resolves": True, "a": [f"1.1.1.{i}"]}
            for i in range(15)
        ]
        result = {
            "records": full_records[:10],
            "omitted_records": 5,
            "_full_evidence": {"records": full_records},
            "evidence_id": "dnsx:example.com",
        }
        facts = tool.extract_facts({"target": "example.com"}, result)
        assert len(facts) == 15
        assert facts[14]["host"] == "sub14.example.com"
        assert facts[14]["evidence"] == "dnsx:example.com"

    def test_extract_facts(self):
        tool = Dnsx()
        result = {
            "records": [
                {
                    "host": "examplepaint.com.br",
                    "resolves": True,
                    "a": ["192.0.2.10"],
                    "mx": ["mx.core.examplehost.net"],
                },
                {
                    "host": "dead.examplepaint.com.br",
                    "resolves": False,
                },
            ],
            "evidence_id": "dnsx:examplepaint.com.br",
        }
        facts = tool.extract_facts({"target": "examplepaint.com.br"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "examplepaint.com.br"
        assert fact["port"] == 53
        assert fact["dns_a"] == "192.0.2.10"
        assert fact["dns_mx"] == "mx.core.examplehost.net"
        assert fact["evidence"] == "dnsx:examplepaint.com.br"
