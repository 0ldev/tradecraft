"""Tests for Phase 4: target knowledge graph."""
import json

from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.facts import FactStore
from tradecraft.memory.graph import TargetGraph
from tradecraft.memory.log import EngagementMemory


def _build(tmp_path):
    facts = FactStore()
    facts.merge_port("10.0.0.5", 80, {"http_title": "Login"})
    facts.merge_port("10.0.0.5", 22, {"banner": "OpenSSH"})
    facts.merge_port("app.local", 443, {"http_title": "App"})
    memory = EngagementMemory()
    evidence = EvidenceStore(persist_dir=str(tmp_path / "ev"))
    eid = evidence.save("10.0.0.5", "nmap_scan", {"ports": [80, 22]})
    memory.finding("SQLi on 10.0.0.5:80 confirmed", evidence_id=eid)
    memory.finding("Unrelated observation")
    return TargetGraph.from_engagement(facts, memory, evidence, target="10.0.0.5")


def test_graph_nodes_and_edges(tmp_path):
    graph = _build(tmp_path)
    labels = {n["label"] for n in graph.services()}
    assert labels == {"10.0.0.5:80", "10.0.0.5:22", "app.local:443"}
    # host nodes: engagement root + 10.0.0.5 + app.local
    hosts = [n for n in graph.nodes.values() if n["type"] == "host"]
    assert len(hosts) == 3


def test_finding_attached_to_named_service(tmp_path):
    graph = _build(tmp_path)
    finding_edges = [e for e in graph.edges if e["kind"] == "finding_on"]
    # The SQLi finding names 10.0.0.5:80 exactly -> attaches to that service.
    attached = {e["dst"] for e in finding_edges}
    assert "finding:1" in attached
    edge = next(e for e in finding_edges if e["dst"] == "finding:1")
    assert edge["src"] == "service:10.0.0.5:80"


def test_ambiguous_finding_attaches_to_root(tmp_path):
    facts = FactStore()
    facts.merge_port("10.0.0.5", 80, {"http_title": "A"})
    facts.merge_port("10.0.0.5", 8080, {"http_title": "B"})
    memory = EngagementMemory()
    memory.finding("both 10.0.0.5:80 and 10.0.0.5:8080 affected")
    graph = TargetGraph.from_engagement(facts, memory)
    edge = next(e for e in graph.edges if e["dst"] == "finding:1")
    assert edge["src"] == "engagement"


def test_save_load_roundtrip(tmp_path):
    graph = _build(tmp_path)
    path = tmp_path / "graph.json"
    graph.save(path)
    loaded = TargetGraph.load(path)
    assert loaded.summary() == graph.summary()
    assert json.loads(path.read_text())["edges"]


def test_render_seed_structured_and_compact(tmp_path):
    graph = _build(tmp_path)
    text = graph.render_seed()
    assert "10.0.0.5:80" in text
    assert "FINDING: SQLi on 10.0.0.5:80 confirmed" in text


def test_diff_against_prior_run(tmp_path):
    old = _build(tmp_path)
    # New run: one more service, one more finding.
    facts = FactStore()
    facts.merge_port("10.0.0.5", 80, {"http_title": "Login"})
    facts.merge_port("10.0.0.5", 22, {"banner": "OpenSSH"})
    facts.merge_port("app.local", 443, {"http_title": "App"})
    facts.merge_port("10.0.0.5", 8443, {"http_title": "New"})
    memory = EngagementMemory()
    memory.finding("SQLi on 10.0.0.5:80 confirmed")
    memory.finding("New: RCE on 10.0.0.5:8443")
    new = TargetGraph.from_engagement(facts, memory)
    diff = new.diff_against(old)
    assert "10.0.0.5:8443" in diff["new_services"]
    assert any("RCE" in f for f in diff["new_findings"])
