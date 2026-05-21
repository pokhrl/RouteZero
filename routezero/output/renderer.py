"""
routezero/output/renderer.py
Terminal and JSON rendering for analysis results.
"""
from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from routezero.core.engine import AnalysisReport, AttackPath
    from routezero.core.graph import AttackGraph

# ── ANSI colours (graceful fallback if terminal doesn't support them) ─────

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GREY   = "\033[90m"


def _severity_color(score: float) -> str:
    if score >= 80:
        return RED
    if score >= 50:
        return YELLOW
    return GREEN


def _effort_label(effort: str) -> str:
    colors = {"LOW": RED, "MEDIUM": YELLOW, "HIGH": GREEN}
    c = colors.get(effort.upper(), GREY)
    return f"{c}{effort}{RESET}"


# ── Public renderers ──────────────────────────────────────────────────────

def render_report(report: "AnalysisReport", graph: "AttackGraph") -> None:
    """Print a human-friendly report to stdout."""
    stats = report.graph_stats
    print(f"\n{BOLD}{CYAN}RouteZero Attack-Path Analysis{RESET}")
    print(f"{GREY}{'─' * 60}{RESET}")
    print(f"  Nodes : {stats.get('nodes', '?')}   "
          f"Edges : {stats.get('edges', '?')}   "
          f"Density : {stats.get('density', '?')}")
    print(f"{GREY}{'─' * 60}{RESET}\n")

    if not report.paths:
        print(f"{YELLOW}No attack paths discovered.{RESET}\n")
        return

    for ap in report.paths:
        col = _severity_color(ap.score)
        label = "CRITICAL" if ap.score >= 80 else ("HIGH" if ap.score >= 50 else "MEDIUM")
        print(f"{col}{BOLD}[{label}] Attack Path #{ap.rank}{RESET}")
        print(f"  Score  : {col}{ap.score}{RESET}")
        print(f"  Effort : {_effort_label(ap.effort)}")
        print(f"  Type   : {ap.path_type}")
        print()
        _render_path_tree(ap, graph)
        print()
        if ap.impact_summary:
            print(f"  {GREY}Impact:{RESET} {ap.impact_summary}")
        print(f"{GREY}{'─' * 60}{RESET}\n")


def _render_path_tree(ap: "AttackPath", graph: "AttackGraph") -> None:
    seq = ap.node_sequence(graph)
    edges = ap.edges
    indent = "  "
    for i, node_label in enumerate(seq):
        prefix = "└─" if i == len(seq) - 1 else "├─"
        if i == 0:
            print(f"{indent}{BOLD}{node_label}{RESET}")
        else:
            edge_label = edges[i - 1].edge_type if i - 1 < len(edges) else ""
            diff = edges[i - 1].difficulty if i - 1 < len(edges) else ""
            diff_str = f" [{diff}]" if diff else ""
            print(f"{indent}{'   ' * (i - 1)} {prefix} {GREY}{edge_label}{diff_str}{RESET}")
            print(f"{indent}{'   ' * i}   {BOLD}{node_label}{RESET}")


def render_stats(graph: "AttackGraph") -> None:
    stats = graph.stats()
    print(f"\n{BOLD}{CYAN}RouteZero Graph Statistics{RESET}")
    print(f"{GREY}{'─' * 40}{RESET}")
    for k, v in stats.items():
        if isinstance(v, dict):
            print(f"  {k}:")
            for kk, vv in v.items():
                print(f"    {kk}: {vv}")
        else:
            print(f"  {k}: {v}")
    print()


def render_json(report: "AnalysisReport", graph: "AttackGraph") -> None:
    print(json.dumps(report.to_dict(graph), indent=2))


def render_dot(graph: "AttackGraph") -> str:
    """Return a Graphviz DOT representation of the graph."""
    lines = ["digraph RouteZero {", '  rankdir=LR;', '  node [shape=box];']
    for node in graph.nodes.values():
        label = node.display_label().replace('"', '\\"')
        shape = {
            "vulnerability": "diamond",
            "credential":    "ellipse",
            "data":          "cylinder",
        }.get(node.type, "box")
        lines.append(f'  "{node.id}" [label="{label}" shape={shape}];')
    for edge in graph.edges:
        lines.append(
            f'  "{edge.src}" -> "{edge.dst}" [label="{edge.edge_type}"];'
        )
    lines.append("}")
    return "\n".join(lines)
