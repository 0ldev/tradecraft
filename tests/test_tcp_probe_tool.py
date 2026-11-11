"""
Unit tests for TcpProbe tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.tcp_probe.execute import ProbeResult
from tradecraft.tools.tcp_probe import TcpProbe


def test_tcp_probe_run_success():
    tool = TcpProbe()
    fake_result = ProbeResult(
        target="example.com",
        host="example.com",
        port=80,
        connected=True,
        ssl_used=False,
        status="open",
        banner_bytes=b"HTTP/1.1 200 OK",
        banner_hex="48545450",
        banner_text="HTTP/1.1 200 OK",
        rtt_ms=45.2,
    )

    with patch("tradecraft.tools.tcp_probe.tcp_execute", return_value=fake_result):
        res = tool.run(target="example.com", port=80)
        assert res["status"] == "open"
        assert res["service"] == "http"
        assert "_full_evidence" in res


def test_tcp_probe_extract_evidence():
    tool = TcpProbe()
    fake_full = {"status": "open", "banner_text": "SSH-2.0-OpenSSH"}
    result_dict = {"_full_evidence": fake_full, "host": "192.168.1.1"}

    ev = tool.extract_evidence({"target": "192.168.1.1", "port": 22}, result_dict)
    assert ev is not None
    assert ev[0] == "192.168.1.1"
    assert ev[1] == fake_full
    assert "_full_evidence" not in result_dict


def test_tcp_probe_extract_facts_open_and_closed():
    tool = TcpProbe()

    facts_open = tool.extract_facts(
        {"target": "example.com", "port": 22},
        {"host": "example.com", "port": 22, "status": "open", "service": "ssh", "banner": "SSH-2.0"},
    )
    assert len(facts_open) == 1
    assert facts_open[0]["state"] == "open"
    assert facts_open[0]["service"] == "ssh"

    # Closed by peer (tcpwrapped)
    facts_closed = tool.extract_facts(
        {"target": "examplepaint.com.br", "port": 1001},
        {"host": "examplepaint.com.br", "port": 1001, "status": "closed_by_peer"},
    )
    assert len(facts_closed) == 1
    assert facts_closed[0]["state"] == "closed"
