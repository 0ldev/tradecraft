import json

from tradecraft.execution.loop import _dispatch_tool
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.facts import FactStore
from tradecraft.tools.base import Tool
from tradecraft.tools.evidence_tools import ReadEvidence, SearchEvidence


class DummyEvidenceTool(Tool):
    tool_id = "testssl"

    def run(self, target: str):
        return {
            "target": target,
            "findings": [{"id": "rc4", "severity": "HIGH"}],
            "_evidence": {"full_ciphers": ["RC4-SHA", "AES-GCM"]},
        }

    def extract_evidence(self, params, result):
        ev = result.pop("_evidence", None)
        return params["target"], ev

    def extract_facts(self, params, result):
        fact = {"host": params["target"], "port": 443}
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]


def test_dispatch_tool_saves_evidence_and_updates_facts_and_enables_retrieval(tmp_path):
    facts = FactStore()
    evidence = EvidenceStore(persist_dir=tmp_path)

    tool = DummyEvidenceTool()
    tool_map = {
        "testssl": tool,
        "read_evidence": ReadEvidence(evidence),
        "search_evidence": SearchEvidence(evidence),
    }

    # 1. Dispatch tool
    result = _dispatch_tool("testssl", {"target": "example.com"}, tool_map, facts, evidence=evidence)

    assert result["evidence_id"] == "testssl:example.com"
    assert "_evidence" not in result  # Popped out of conversation payload

    # 2. Check facts store has the pointer
    rendered_facts = facts.render()
    assert "evidence=testssl:example.com" in rendered_facts

    # 3. Retrieve using read_evidence
    retrieved = _dispatch_tool(
        "read_evidence", {"target": "example.com", "tool_id": "testssl"}, tool_map, facts, evidence=evidence
    )
    assert retrieved["target"] == "example.com"
    assert retrieved["evidence"]["full_ciphers"] == ["RC4-SHA", "AES-GCM"]

    search_res = _dispatch_tool(
        "search_evidence", {"query": "RC4-SHA"}, tool_map, facts, evidence=evidence
    )
    assert search_res["total_matches"] >= 1
    assert "RC4-SHA" in search_res["matches"][0]["match"]


class DummyBatchEvidenceTool(Tool):
    """Mimics the real batch-key-mismatch bug class (dnsx, httpx_probe,
    http_request, subzy, shodan_internetdb): one call covers several
    independent targets, saved under only the first via a 3-tuple
    (target, data, aliases) extract_evidence return. Borrows
    shodan_internetdb's tool_id (a real ALL_TOOLS entry, needed for
    ReadEvidence's validation) specifically because it has no
    required_binary gate -- keeps this test's result independent of
    which scanner binaries happen to be installed in the environment
    it runs in."""

    tool_id = "shodan_internetdb"

    def run(self, ip: str):
        hosts = [h.strip() for h in ip.split(",")]
        return {
            "ip": ip,
            "results": [{"host": h, "status_code": 200} for h in hosts],
            "_evidence": {"ip": ip, "results": [{"host": h, "status_code": 200} for h in hosts]},
        }

    def extract_evidence(self, params, result):
        hosts = [h.strip() for h in params["ip"].split(",")]
        ev = result.pop("_evidence", None)
        return hosts[0], ev, hosts[1:]

    def extract_facts(self, params, result):
        facts = []
        for entry in result.get("results", []):
            fact = {"host": entry["host"], "port": 443}
            if result.get("evidence_id"):
                fact["evidence"] = result["evidence_id"]
            facts.append(fact)
        return facts


def test_dispatch_tool_batch_alias_makes_every_host_retrievable(tmp_path):
    """Regression for the real example.com/example.ai eval findings
    (2026-11-04): before this fix, every non-first host in a batch call
    got a fact pointing at an evidence_id that read_evidence could never
    actually resolve. This exercises the full path the model would
    actually hit: dispatch the batch tool, then read_evidence on a
    non-canonical host."""
    facts = FactStore()
    evidence = EvidenceStore(persist_dir=tmp_path)
    tool_map = {
        "shodan_internetdb": DummyBatchEvidenceTool(),
        "read_evidence": ReadEvidence(evidence),
    }

    result = _dispatch_tool(
        "shodan_internetdb", {"ip": "first.example.com,second.example.com,third.example.com"},
        tool_map, facts, evidence=evidence,
    )
    assert result["evidence_id"] == "shodan_internetdb:first.example.com"

    # Every host's fact carries the same (canonical) evidence_id...
    rendered = facts.render()
    assert "second.example.com" in rendered
    assert "third.example.com" in rendered

    # The canonical host gets a direct hit: the whole batch blob (its own
    # record is in there, among the rest).
    direct = _dispatch_tool(
        "read_evidence", {"target": "first.example.com", "tool_id": "shodan_internetdb"}, tool_map, facts, evidence=evidence
    )
    assert "error" not in direct
    assert {"host": "first.example.com", "status_code": 200} in direct["evidence"]["results"]

    # Each non-canonical host must still resolve to real, host-scoped
    # data via the alias stub -- not "no evidence found".
    for host in ("second.example.com", "third.example.com"):
        retrieved = _dispatch_tool(
            "read_evidence", {"target": host, "tool_id": "shodan_internetdb"}, tool_map, facts, evidence=evidence
        )
        assert "error" not in retrieved, f"{host}: {retrieved}"
        assert retrieved["evidence"]["host"] == host


class DummyTruncatingBatchTool(Tool):
    """Mimics the real display-truncation bug class (httpx_probe, dnsx,
    http_request): a batch call with more members than the tool's own
    display cap keeps the full list internally (`_full_evidence`) for the
    EvidenceStore, but caps what's shown in the model-facing result. Before
    the fix, extract_facts read only the capped `results` list, so every
    host past the cap got no FactStore row at all -- not even a bare
    pointer -- despite its full data being retrievable via read_evidence.
    Borrows shodan_internetdb's tool_id (a real ALL_TOOLS entry, needed for
    ReadEvidence's validation) specifically because it has no
    required_binary gate -- keeps this test's result independent of which
    scanner binaries happen to be installed in the environment it runs
    in (same reasoning as DummyBatchEvidenceTool above)."""

    tool_id = "shodan_internetdb"
    DISPLAY_CAP = 2

    def run(self, ip: str):
        hosts = [h.strip() for h in ip.split(",")]
        full_results = [{"host": h, "status_code": 200} for h in hosts]
        res = {"ip": ip, "probed_count": len(hosts)}
        if len(full_results) > self.DISPLAY_CAP:
            res["results"] = full_results[: self.DISPLAY_CAP]
            res["omitted_results"] = len(full_results) - self.DISPLAY_CAP
        else:
            res["results"] = full_results
        res["_full_evidence"] = {"ip": ip, "results": full_results}
        return res

    def extract_evidence(self, params, result):
        hosts = [h.strip() for h in params["ip"].split(",")]
        full = result.get("_full_evidence")  # peek, not pop
        if full is None:
            return None
        return hosts[0], full, hosts[1:]

    def extract_facts(self, params, result):
        full_evidence = result.get("_full_evidence")
        entries = full_evidence["results"] if full_evidence else result.get("results", [])
        facts = []
        for entry in entries:
            fact = {"host": entry["host"], "port": 443}
            if result.get("evidence_id"):
                fact["evidence"] = result["evidence_id"]
            facts.append(fact)
        return facts


def test_dispatch_tool_facts_cover_batch_members_past_display_truncation(tmp_path):
    """Regression for a real eval finding (2026-11-05):
    httpx_probe/dnsx/http_request each cap how many batch members they show
    in the model-facing result (to conserve context), but before this fix
    extract_facts derived FactStore rows from that same capped list -- so a
    host past the cap had no row in Known Facts at all (not trimmed, never
    written), even though read_evidence could still retrieve its full data.
    This exercises the full dispatch path and confirms every batch member
    gets a fact, while `_full_evidence` still never reaches the model."""
    facts = FactStore()
    evidence = EvidenceStore(persist_dir=tmp_path)
    tool_map = {
        "shodan_internetdb": DummyTruncatingBatchTool(),
        "read_evidence": ReadEvidence(evidence),
    }

    result = _dispatch_tool(
        "shodan_internetdb", {"ip": "a.example.com,b.example.com,c.example.com,d.example.com"},
        tool_map, facts, evidence=evidence,
    )

    # Display truncation still happens -- this isn't about removing it.
    assert len(result["results"]) == 2
    assert result["omitted_results"] == 2
    # But it must never leak into what's sent back to the model.
    assert "_full_evidence" not in result

    # Every batch member -- including the two past the display cap --
    # gets a FactStore row with a working evidence pointer, not silence.
    rendered = facts.render()
    for host in ("a.example.com", "b.example.com", "c.example.com", "d.example.com"):
        assert host in rendered

    for host in ("c.example.com", "d.example.com"):
        retrieved = _dispatch_tool(
            "read_evidence", {"target": host, "tool_id": "shodan_internetdb"}, tool_map, facts, evidence=evidence
        )
        assert "error" not in retrieved, f"{host}: {retrieved}"


class DummyGenericTool(Tool):
    tool_id = "host_header_injection_probe"

    def run(self, target: str):
        return {"target": target, "status": "exposed", "data": "critical_value"}


def test_default_extract_evidence_for_tools_without_custom_override(tmp_path):
    """Verifies that Tool base class automatically offloads evidence and assigns
    evidence_id for tools that do not define a custom extract_evidence override."""
    facts = FactStore()
    evidence = EvidenceStore(persist_dir=tmp_path)
    tool = DummyGenericTool()
    tool_map = {
        "host_header_injection_probe": tool,
        "read_evidence": ReadEvidence(evidence),
    }

    result = _dispatch_tool(
        "host_header_injection_probe",
        {"target": "203.0.113.41"},
        tool_map,
        facts,
        evidence=evidence,
    )

    assert result["evidence_id"] == "host_header_injection_probe:203.0.113.41"
    assert evidence.has_evidence("host_header_injection_probe:203.0.113.41") is True

    read_res = _dispatch_tool(
        "read_evidence",
        {"target": "203.0.113.41", "tool_id": "host_header_injection_probe"},
        tool_map,
        facts,
        evidence=evidence,
    )
    assert read_res["target"] == "203.0.113.41"
    assert read_res["evidence"]["data"] == "critical_value"


def test_nmap_scan_attaches_evidence_id_to_facts(tmp_path):
    from tradecraft.tools.nmap_scan import NmapScan

    tool = NmapScan()
    facts = tool.extract_facts(
        {"target": "203.0.113.41"},
        {
            "target": "203.0.113.41",
            "ports": [{"port": 3306, "state": "open", "service": "mysql", "version": "11.8.9-MariaDB"}],
            "evidence_id": "nmap_scan:203.0.113.41",
        },
    )
    assert len(facts) == 1
    assert facts[0]["host"] == "203.0.113.41"
    assert facts[0]["port"] == 3306
    assert facts[0]["evidence"] == "nmap_scan:203.0.113.41"


def test_azure_tenant_recon_extract_facts_and_evidence(tmp_path):
    from tradecraft.tools.azure_tenant_recon import AzureTenantRecon

    tool = AzureTenantRecon()
    facts = tool.extract_facts(
        {"domain": "example.com.br"},
        {
            "domain": "example.com.br",
            "is_azure_ad": True,
            "tenant_id": "11111111-2222-3333-4444-555555555555",
            "existing_usernames": ["finance@example.com.br", "hr@example.com.br"],
            "evidence_id": "azure_tenant_recon:example.com.br",
        },
    )
    assert len(facts) == 1
    assert facts[0]["host"] == "example.com.br"
    assert facts[0]["port"] == 443
    assert facts[0]["azure_ad_tenant"] == "11111111-2222-3333-4444-555555555555"
    assert "finance@example.com.br" in facts[0]["azure_ad_users"]
    assert facts[0]["evidence"] == "azure_tenant_recon:example.com.br"

