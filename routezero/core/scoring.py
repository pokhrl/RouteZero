"""
routezero/core/scoring.py
Attack-path risk scoring model (0–100).
"""
from __future__ import annotations

from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from routezero.core.graph import AttackGraph, Edge

# ── Weight tables ─────────────────────────────────────────────────────────

EDGE_TYPE_WEIGHTS = {
    "privilege_escalation": 2.0,
    "data_access":          1.8,
    "credential_use":       1.6,
    "lateral_movement":     1.4,
    "exploits":             1.2,
    "network_access":       1.0,
}

DIFFICULTY_MULTIPLIERS = {
    "low":    1.30,
    "medium": 1.00,
    "high":   0.65,
}


def score_path(path: List["Edge"], graph: "AttackGraph") -> float:
    """Return a risk score 0–100 for an edge-path."""
    if not path:
        return 0.0

    # 1. CVSS contribution — average of vulnerability nodes touched
    cvss_values = []
    for edge in path:
        node = graph.nodes.get(edge.src)
        if node and node.type == "vulnerability" and node.cvss > 0:
            cvss_values.append(node.cvss)
    avg_cvss = (sum(cvss_values) / len(cvss_values)) if cvss_values else 5.0
    cvss_score = (avg_cvss / 10.0) * 40.0          # up to 40 pts

    # 2. Edge-type contribution
    edge_weight_sum = sum(
        EDGE_TYPE_WEIGHTS.get(e.edge_type, 1.0) for e in path
    )
    edge_score = min(edge_weight_sum * 3.0, 30.0)   # up to 30 pts

    # 3. Chain-length bonus (longer validated chains → higher impact)
    length_score = min(len(path) * 2.5, 20.0)       # up to 20 pts

    # 4. Difficulty multiplier (average across path)
    avg_difficulty = sum(
        DIFFICULTY_MULTIPLIERS.get(e.difficulty.lower(), 1.0) for e in path
    ) / len(path)

    raw = (cvss_score + edge_score + length_score) * avg_difficulty
    return round(min(raw, 100.0), 1)


def effort_label(score: float) -> str:
    if score >= 80:
        return "LOW"
    if score >= 50:
        return "MEDIUM"
    return "HIGH"
