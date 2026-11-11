"""
Unit tests for HttpSmugglingProbe tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.http_smuggling_probe.execute import SmugglingProbeRun, VariantResult
from tradecraft.tools.http_smuggling_probe import HttpSmugglingProbe


def _run(verdict_cl_te_responses: int, verdict_te_cl_responses: int, error=None) -> SmugglingProbeRun:
    return SmugglingProbeRun(
        target="examplepaint.com.br",
        host="examplepaint.com.br",
        port=443,
        ssl_used=True,
        nonce="abcdef012345",
        timeout_s=5.0,
        error=error,
        variants=[
            VariantResult(
                variant="cl_te", status="ok", connected=True,
                request_head="POST / HTTP/1.1\r\nHost: examplepaint.com.br",
                responses_seen=verdict_cl_te_responses,
                status_codes=[404] * verdict_cl_te_responses,
                bytes_received=120, first_response_ms=30.0, elapsed_ms=35.0,
                response_head=b"HTTP/1.1 404 Not Found\r\n",
            ),
            VariantResult(
                variant="te_cl", status="ok", connected=True,
                request_head="POST / HTTP/1.1\r\nHost: examplepaint.com.br",
                responses_seen=verdict_te_cl_responses,
                status_codes=[404] * verdict_te_cl_responses,
                bytes_received=120, first_response_ms=29.0, elapsed_ms=34.0,
                response_head=b"HTTP/1.1 404 Not Found\r\n",
            ),
        ],
    )


def test_http_smuggling_probe_run_clean():
    tool = HttpSmugglingProbe()
    with patch("tradecraft.tools.http_smuggling_probe.smuggling_execute", return_value=_run(1, 1)):
        res = tool.run(target="examplepaint.com.br")
    assert res["verdict"] == "no_discrepancy_detected"
    assert len(res["variants"]) == 2
    assert "_full_evidence" in res


def test_http_smuggling_probe_run_flags_cl_te():
    tool = HttpSmugglingProbe()
    with patch("tradecraft.tools.http_smuggling_probe.smuggling_execute", return_value=_run(2, 1)):
        res = tool.run(target="examplepaint.com.br")
    assert res["verdict"] == "likely_cl_te"


def test_http_smuggling_probe_run_passes_clamped_timeout_and_port():
    tool = HttpSmugglingProbe()
    with patch("tradecraft.tools.http_smuggling_probe.smuggling_execute", return_value=_run(1, 1)) as ex:
        tool.run(target="examplepaint.com.br", port=80, ssl_probe=False, timeout=7)
    ex.assert_called_once_with(target="examplepaint.com.br", port=80, ssl_probe=False, timeout=7)


def test_http_smuggling_probe_extract_evidence():
    tool = HttpSmugglingProbe()
    with patch("tradecraft.tools.http_smuggling_probe.smuggling_execute", return_value=_run(1, 1)):
        res = tool.run(target="examplepaint.com.br")
    ev = tool.extract_evidence({"target": "examplepaint.com.br"}, res)
    assert ev is not None
    assert ev[0] == "examplepaint.com.br"
    assert ev[1]["nonce"] == "abcdef012345"
    assert len(ev[1]["variants"]) == 2
    assert "_full_evidence" not in res


def test_http_smuggling_probe_extract_facts_only_on_positive():
    tool = HttpSmugglingProbe()
    facts_pos = tool.extract_facts(
        {"target": "examplepaint.com.br"},
        {"host": "examplepaint.com.br", "port": 443, "verdict": "likely_te_cl"},
    )
    assert facts_pos == [{"host": "examplepaint.com.br", "port": 443, "http_smuggling": "likely_te_cl"}]

    facts_neg = tool.extract_facts(
        {"target": "examplepaint.com.br"},
        {"host": "examplepaint.com.br", "port": 443, "verdict": "no_discrepancy_detected"},
    )
    assert facts_neg == []
