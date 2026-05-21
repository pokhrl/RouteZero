"""
routezero/core/graph.py
Directed attack graph construction and traversal.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


# ── Node / Edge models ────────────────────────────────────────────────────

@dataclass
class Node:
    id: str
    type: str                            # network | host | vulnerability | credential | data
    label: str = ""
    cvss: float = 0.0
    cve_id: str = ""
    os: str = ""
    services: List[str] = field(default_factory=list)
    privilege_level: str = ""
    sensitivity: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def display_label(self) -> str:
        return self.label or self.id


@dataclass
class Edge:
    src: str
    dst: str
    edge_type: str          # network_access | exploits | privilege_escalation |
                            # credential_use | lateral_movement | data_access
    difficulty: str = "medium"   # low | medium | high
    requires: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)


# ── Attack Graph ──────────────────────────────────────────────────────────

class AttackGraph:
    """Directed graph of hosts, vulnerabilities, credentials, and data."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self._adj: Dict[str, List[Edge]] = {}   # src -> edges

    # ── Construction ──────────────────────────────────────────────────

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node
        self._adj.setdefault(node.id, [])

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)
        self._adj.setdefault(edge.src, []).append(edge)
        self._adj.setdefault(edge.dst, [])   # ensure dst exists in adj

    # ── Traversal ─────────────────────────────────────────────────────

    def neighbors(self, node_id: str) -> List[Edge]:
        return self._adj.get(node_id, [])

    def all_paths(
        self,
        start: str,
        max_depth: int = 15,
    ) -> List[List[Edge]]:
        """Return all simple edge-paths from *start* using DFS."""
        results: List[List[Edge]] = []
        visited: Set[str] = set()

        def dfs(current: str, path: List[Edge]) -> None:
            if len(path) >= max_depth:
                return
            visited.add(current)
            for edge in self.neighbors(current):
                if edge.dst not in visited:
                    path.append(edge)
                    results.append(list(path))
                    dfs(edge.dst, path)
                    path.pop()
            visited.discard(current)

        dfs(start, [])
        return results

    # ── Statistics ────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        n = len(self.nodes)
        e = len(self.edges)
        max_possible = n * (n - 1) if n > 1 else 1
        return {
            "nodes": n,
            "edges": e,
            "density": round(e / max_possible, 4),
            "node_types": self._count_types(),
        }

    def _count_types(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for node in self.nodes.values():
            counts[node.type] = counts.get(node.type, 0) + 1
        return counts

    # ── Serialization ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": n.id, "type": n.type, "label": n.label,
                    "cvss": n.cvss, "cve_id": n.cve_id,
                    "os": n.os, "services": n.services,
                    "privilege_level": n.privilege_level,
                    "sensitivity": n.sensitivity, **n.extra,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "from": e.src, "to": e.dst,
                    "edge_type": e.edge_type, "difficulty": e.difficulty,
                    "requires": e.requires, **e.extra,
                }
                for e in self.edges
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackGraph":
        g = cls()
        for raw in data.get("nodes", []):
            known = {"id", "type", "label", "cvss", "cve_id", "os",
                     "services", "privilege_level", "sensitivity"}
            extra = {k: v for k, v in raw.items() if k not in known}
            g.add_node(Node(
                id=raw["id"],
                type=raw.get("type", "host"),
                label=raw.get("label", ""),
                cvss=float(raw.get("cvss", 0.0)),
                cve_id=raw.get("cve_id", ""),
                os=raw.get("os", ""),
                services=raw.get("services", []),
                privilege_level=raw.get("privilege_level", ""),
                sensitivity=raw.get("sensitivity", ""),
                extra=extra,
            ))
        for raw in data.get("edges", []):
            known = {"from", "to", "edge_type", "difficulty", "requires"}
            extra = {k: v for k, v in raw.items() if k not in known}
            g.add_edge(Edge(
                src=raw["from"],
                dst=raw["to"],
                edge_type=raw.get("edge_type", "network_access"),
                difficulty=raw.get("difficulty", "medium"),
                requires=raw.get("requires", []),
                extra=extra,
            ))
        return g

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "AttackGraph":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))
