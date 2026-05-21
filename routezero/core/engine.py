"""
routezero/core/engine.py
Core analysis engine: discovers, classifies, and ranks attack paths.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from routezero.core.graph import AttackGraph, Edge
from routezero.core.scoring import effort_label, score_path


# ── Result models ─────────────────────────────────────────────────────────

@dataclass
class AttackPath:
    rank: int
    score: float
    effort: str
    path_type: str            # escalation | lateral | exposure | mixed
    edges: List[Edge]
    impact_summary: str = ""

    def node_sequence(self, graph: AttackGraph) -> List[str]:
        if not self.edges:
            return []
        seq = [self.edges[0].src]
        for e in self.edges:
            seq.append(e.dst)
        return [graph.nodes[n].display_label() if n in graph.nodes else n
                for n in seq]

    def to_dict(self, graph: AttackGraph) -> Dict[str, Any]:
        return {
            "rank":   self.rank,
            "score":  self.score,
            "effort": self.effort,
            "type":   self.path_type,
            "nodes":  self.node_sequence(graph),
            "edges":  [
                {"from": e.src, "to": e.dst,
                 "type": e.edge_type, "difficulty": e.difficulty}
                for e in self.edges
            ],
            "impact": self.impact_summary,
        }


@dataclass
class AnalysisReport:
    paths: List[AttackPath]
    graph_stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, graph: AttackGraph) -> Dict[str, Any]:
        return {
            "stats": self.graph_stats,
            "paths": [p.to_dict(graph) for p in self.paths],
        }


# ── Classification helpers ────────────────────────────────────────────────

_ESCALATION_EDGES  = {"privilege_escalation", "credential_use"}
_LATERAL_EDGES     = {"lateral_movement", "network_access"}
_EXPOSURE_EDGES    = {"data_access"}


def _classify_path(edges: List[Edge]) -> str:
    types = {e.edge_type for e in edges}
    has_esc  = bool(types & _ESCALATION_EDGES)
    has_lat  = bool(types & _LATERAL_EDGES)
    has_exp  = bool(types & _EXPOSURE_EDGES)

    if has_exp and has_esc:
        return "escalation"
    if has_exp:
        return "exposure"
    if has_esc:
        return "escalation"
    if has_lat:
        return "lateral"
    return "mixed"


def _build_impact(edges: List[Edge], graph: AttackGraph) -> str:
    parts: List[str] = []
    types = {e.edge_type for e in edges}

    vuln_nodes = [
        graph.nodes[e.src] for e in edges
        if e.src in graph.nodes and graph.nodes[e.src].type == "vulnerability"
    ]
    if vuln_nodes:
        cves = [n.cve_id for n in vuln_nodes if n.cve_id]
        if cves:
            parts.append(f"Exploits {', '.join(cves[:3])}")
        else:
            parts.append("Vulnerability exploitation")

    if "privilege_escalation" in types or "credential_use" in types:
        parts.append("leading to privilege escalation")
    if "lateral_movement" in types:
        parts.append("and lateral movement")
    if "data_access" in types:
        parts.append("with sensitive data exposure")

    return " ".join(parts) + "." if parts else "Multi-stage attack chain."


# ── Engine ────────────────────────────────────────────────────────────────

class AnalysisEngine:
    """Discovers and ranks attack paths in an AttackGraph."""

    ATTACKER_NODE_TYPES = {"network", "attacker", "external"}

    def __init__(self, graph: AttackGraph) -> None:
        self.graph = graph

    def _attacker_roots(self) -> List[str]:
        roots = [
            nid for nid, node in self.graph.nodes.items()
            if node.type in self.ATTACKER_NODE_TYPES
               or nid.lower() in {"attacker", "external", "internet"}
        ]
        # Fallback: nodes with no incoming edges
        if not roots:
            dst_ids = {e.dst for e in self.graph.edges}
            roots = [nid for nid in self.graph.nodes if nid not in dst_ids]
        return roots or list(self.graph.nodes.keys())[:1]

    def analyze(
        self,
        path_type: str = "all",
        top_n: int = 10,
    ) -> AnalysisReport:
        all_paths: List[AttackPath] = []

        for root in self._attacker_roots():
            for edge_list in self.graph.all_paths(root):
                ptype = _classify_path(edge_list)
                if path_type != "all" and ptype != path_type:
                    continue

                score = score_path(edge_list, self.graph)
                all_paths.append(AttackPath(
                    rank=0,
                    score=score,
                    effort=effort_label(score),
                    path_type=ptype,
                    edges=edge_list,
                    impact_summary=_build_impact(edge_list, self.graph),
                ))

        # De-duplicate by node sequence, keep highest score
        seen: Dict[tuple, AttackPath] = {}
        for ap in all_paths:
            key = tuple(e.src + "->" + e.dst for e in ap.edges)
            if key not in seen or ap.score > seen[key].score:
                seen[key] = ap

        ranked = sorted(seen.values(), key=lambda x: x.score, reverse=True)
        for i, ap in enumerate(ranked[:top_n], 1):
            ap.rank = i

        return AnalysisReport(
            paths=ranked[:top_n],
            graph_stats=self.graph.stats(),
        )
