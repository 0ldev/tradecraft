from tradecraft.tools.nmap_scan import NmapScan


def test_extract_facts_attaches_host_to_each_port():
    tool = NmapScan()
    result = {
        "target": "examplepaint.com.br",
        "ports": [
            {"port": 80, "state": "open", "protocol": "tcp", "service": "http", "version": "nginx 1.24.0"},
            {"port": 443, "state": "open", "protocol": "tcp", "service": "https"},
        ],
    }
    facts = tool.extract_facts({"target": "examplepaint.com.br"}, result)

    assert facts == [
        {"host": "examplepaint.com.br", "port": 80, "state": "open", "service": "http", "version": "nginx 1.24.0"},
        {"host": "examplepaint.com.br", "port": 443, "state": "open", "service": "https", "version": None},
    ]


def test_extract_facts_strips_explicit_port_from_host():
    tool = NmapScan()
    result = {"target": "examplepaint.com.br:443", "ports": [{"port": 443, "state": "open", "service": "https"}]}
    facts = tool.extract_facts({"target": "examplepaint.com.br:443"}, result)

    assert facts[0]["host"] == "examplepaint.com.br"
    assert facts[0]["port"] == 443


def test_extract_facts_empty_on_error_result():
    tool = NmapScan()
    result = {"target": "examplepaint.com.br", "ports": [], "error": "nmap timed out after 300s"}
    assert tool.extract_facts({"target": "examplepaint.com.br"}, result) == []
