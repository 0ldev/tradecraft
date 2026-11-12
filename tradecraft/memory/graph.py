"""Target knowledge graph (Tradecraft 2.0, Phase 4).

A queryable projection of one engagement's deterministic outputs --
FactStore records and logged findings -- as a small typed graph:

    host --[has_service]--> service(host:port) --[finding]--> finding
                                     |
                                     +--[evidence]--> evidence

Why a graph when FactStore and EngagementMemory already exist? Because
they're flat, and cross-engagement seeding (`--seed-from`) currently
hands the next run a blob of prose. A typed graph can be:
- rendered at whatever detail the consumer needs (`render_seed` vs
  `to_dict` in the Studio UI),
- diffed between runs (same nodes, new edges = previously-known target,
  new findings -- the "continue from where we left off" signal),
- persisted as plain JSON next to the run and reloaded losslessly.

Honest scope note: this is a projection, not new knowledge. Everything
in it was already in facts + memory; the graph adds *shape*, which is
what makes compounding across engagements practical. It never contains
model-invented nodes -- hosts/services come from tool-reported facts,
findings/evidence from the log, same trust rule as everywhere else.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.facts import FactStore
from tradecraft.memory.log import EngagementMemory

TYPE_HOST = "host"
TYPE_SERVICE = "service"
TYPE_FINDING = "finding"
TYPE_EVIDENCE = "evidence"

EDGE_HAS_SERVICE = "has_service"
EDGE_FINDING = "finding_on"
EDGE_EVIDENCE = "evidence_for"


class TargetGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, str]] = []

    # -- construction ------------------------------------------------

    @classmethod
    def from_engagement(
        cls,
        facts: FactStore,
        memory: EngagementMemory,
        evidence: Optional[EvidenceStore] = None,
        target: str = "",
    ) -> "TargetGraph":
        graph = cls()
        root_id = f"engagement:{target}" if target else "engagement"
        graph._add_node(root_id, TYPE_HOST, label=target or "(unnamed)")
        # The engagement root doubles as the top-level host node when the
        # target is a single host; per-host nodes are added from facts.

        seen_hosts: Dict[str, str] = {}
        for (host, port), record in facts.sorted_records():
            host_id = graph._host_node(host, seen_hosts, root_id)
            service_id = f"service:{host}:{port}"
            graph._add_node(service_id, TYPE_SERVICE, label=f"{host}:{port}", data=record)
            graph._add_edge(host_id, service_id, EDGE_HAS_SERVICE)

        for entry in memory.entries:
            if entry.kind != "finding" or entry.retracted or entry.finding_id is None:
                continue
            finding_id = f"finding:{entry.finding_id}"
            graph._add_node(
                finding_id, TYPE_FINDING,
                label=entry.text[:200],
                data={"finding_id": entry.finding_id, "evidence_id": entry.evidence_id},
            )
            # Attach to the service the finding is about, when the text
            # names one deterministically; otherwise to the root.
            attach_id = graph._match_service(entry.text, facts) or root_id
            graph._add_edge(attach_id, finding_id, EDGE_FINDING)
            if entry.evidence_id and evidence is not None and evidence.has_evidence(entry.evidence_id):
                ev_id = f"evidence:{entry.evidence_id}"
                graph._add_node(ev_id, TYPE_EVIDENCE, label=entry.evidence_id)
                graph._add_edge(finding_id, ev_id, EDGE_EVIDENCE)
        return graph

    def _host_node(self, host: str, seen: Dict[str, str], root_id: str) -> str:
        if host in seen:
            return seen[host]
        node_id = f"host:{host}"
        self._add_node(node_id, TYPE_HOST, label=host)
        self._add_edge(root_id, node_id, EDGE_HAS_SERVICE)
        seen[host] = node_id
        return node_id

    def _match_service(self, text: str, facts: FactStore) -> Optional[str]:
        """Attach a finding to the host:port its text names, when exactly
        one service matches -- deterministic substring match, no guessing.
        Multiple matches (or none) attaches to the root instead of
        inventing a relationship."""
        text_l = text.lower()
        matches = []
        for (host, port), _ in facts.sorted_records():
            addr = f"{host}:{port}".lower()
            if addr in text_l:
                matches.append(f"service:{host}:{port}")
        return matches[0] if len(matches) == 1 else None

    def _add_node(self, node_id: str, node_type: str, label: str = "", data: Any = None) -> None:
        if node_id in self.nodes:
            return
        self.nodes[node_id] = {"id": node_id, "type": node_type, "label": label, "data": data}

    def _add_edge(self, src: str, dst: str, kind: str) -> None:
        edge = {"src": src, "dst": dst, "kind": kind}
        if edge not in self.edges:
            self.edges.append(edge)

    # -- persistence --------------------------------------------------

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps({"nodes": list(self.nodes.values()), "edges": self.edges}, default=str),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> "TargetGraph":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        graph = cls()
        for node in raw.get("nodes", []):
            graph.nodes[node["id"]] = node
        graph.edges = raw.get("edges", [])
        return graph

    # -- queries -------------------------------------------------------

    def services(self) -> List[Dict[str, Any]]:
        return [n for n in self.nodes.values() if n["type"] == TYPE_SERVICE]

    def findings(self) -> List[Dict[str, Any]]:
        return [n for n in self.nodes.values() if n["type"] == TYPE_FINDING]

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for node in self.nodes.values():
            counts[node["type"]] = counts.get(node["type"], 0) + 1
        return counts

    def diff_against(self, previous: "TargetGraph") -> Dict[str, List[str]]:
        """What's new relative to a prior run's graph -- the seed-signal
        for 'continue from where we left off'. Pure id-set comparison."""
        return {
            "new_services": sorted(
                {n["label"] for n in self.services()} - {n["label"] for n in previous.services()}
            ),
            "new_findings": sorted(
                {n["label"] for n in self.findings()} - {n["label"] for n in previous.findings()}
            ),
        }

    def render_seed(self, max_chars: int = 4000) -> str:
        """Compact text for the next engagement's seed context: what
        exists (services), what was found (findings). Structured, not
        prose, so it costs the fewest tokens per unit of signal."""
        if not self.nodes:
            return "(no prior knowledge recorded)"
        lines: List[str] = []
        for host_node in (n for n in self.nodes.values() if n["type"] == TYPE_HOST):
            services = [
                e for e in self.edges
                if e["kind"] == EDGE_HAS_SERVICE and e["src"] == host_node["id"]
            ]
            for edge in services:
                svc = self.nodes.get(edge["dst"])
                if not svc:
                    continue
                record = svc.get("data") or {}
                details = ", ".join(
                    f"{k}={v}" for k, v in record.items()
                    if k not in ("host", "port") and v not in (None, "")
                )
                lines.append(f"{svc['label']}" + (f" -- {details}" if details else ""))
        for finding in self.findings():
            lines.append(f"FINDING: {finding['label']}")
        text = "\n".join(lines)
        if len(text) > max_chars:
            text = text[:max_chars] + "\n... (truncated)"
        return text or "(no prior knowledge recorded)"
