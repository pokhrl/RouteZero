"""
tests/test_routezero.py
Comprehensive unit tests for RouteZero.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from routezero.core.graph import AttackGraph, Edge, Node
from routezero.core.scoring import effort_label, score_path
from routezero.core.engine import AnalysisEngine
from routezero.output.renderer import render_dot
from routezero.utils.validator import validate, validate_file

# Repo root = two levels up from this file (tests/test_routezero.py)
REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES  = REPO_ROOT / "examples"


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def simple_graph() -> AttackGraph:
    g = AttackGraph()
    g.add_node(Node(id="attacker", type="network", label="Attacker"))
    g.add_node(Node(id="vuln",    type="vulnerability", cvss=9.0, cve_id="CVE-2021-0001"))
    g.add_node(Node(id="host",   type="host",           label="Target Host"))
    g.add_node(Node(id="creds",  type="credential",     label="Admin Creds"))
    g.add_node(Node(id="db",     type="data",           label="Database"))

    g.add_edge(Edge("attacker", "host",  "network_access",       "low"))
    g.add_edge(Edge("vuln",     "host",  "exploits",             "low"))
    g.add_edge(Edge("host",     "creds", "privilege_escalation", "medium"))
    g.add_edge(Edge("creds",    "db",    "data_access",          "low"))
    return g


@pytest.fixture
def webapp_json_path() -> str:
    return str(EXAMPLES / "webapp_attack.json")


@pytest.fixture
def ad_json_path() -> str:
    return str(EXAMPLES / "ad_escalation.json")


# ── Graph tests ───────────────────────────────────────────────────────────

class TestGraph:
    def test_add_nodes_and_edges(self, simple_graph):
        assert len(simple_graph.nodes) == 5
        assert len(simple_graph.edges) == 4

    def test_neighbors(self, simple_graph):
        neighbors = simple_graph.neighbors("attacker")
        assert any(e.dst == "host" for e in neighbors)

    def test_all_paths_finds_paths(self, simple_graph):
        paths = simple_graph.all_paths("attacker")
        assert len(paths) > 0

    def test_all_paths_max_depth(self, simple_graph):
        paths = simple_graph.all_paths("attacker", max_depth=2)
        assert all(len(p) <= 2 for p in paths)

    def test_stats_keys(self, simple_graph):
        s = simple_graph.stats()
        assert "nodes"      in s
        assert "edges"      in s
        assert "density"    in s
        assert "node_types" in s

    def test_serialization_roundtrip(self, simple_graph):
        d  = simple_graph.to_dict()
        g2 = AttackGraph.from_dict(d)
        assert len(g2.nodes) == len(simple_graph.nodes)
        assert len(g2.edges) == len(simple_graph.edges)

    def test_save_and_load(self, simple_graph, tmp_path):
        p = tmp_path / "graph.json"
        simple_graph.save(str(p))
        g2 = AttackGraph.load(str(p))
        assert len(g2.nodes) == len(simple_graph.nodes)

    def test_empty_graph_stats(self):
        g = AttackGraph()
        s = g.stats()
        assert s["nodes"] == 0
        assert s["edges"] == 0


# ── Scoring tests ─────────────────────────────────────────────────────────

class TestScoring:
    def test_empty_path_scores_zero(self, simple_graph):
        assert score_path([], simple_graph) == 0.0

    def test_score_in_range(self, simple_graph):
        for path in simple_graph.all_paths("attacker"):
            s = score_path(path, simple_graph)
            assert 0.0 <= s <= 100.0, f"Score {s} out of range"

    def test_high_cvss_raises_score(self):
        def make_graph(cvss: float) -> AttackGraph:
            g = AttackGraph()
            g.add_node(Node(id="a", type="network"))
            g.add_node(Node(id="v", type="vulnerability", cvss=cvss))
            g.add_node(Node(id="b", type="host"))
            g.add_edge(Edge("a", "b", "network_access", "low"))
            g.add_edge(Edge("v", "b", "exploits",       "low"))
            return g

        g_high = make_graph(10.0)
        g_low  = make_graph(1.0)
        paths_high = g_high.all_paths("a")
        paths_low  = g_low.all_paths("a")
        assert paths_high and paths_low
        max_high = max(score_path(p, g_high) for p in paths_high)
        max_low  = max(score_path(p, g_low)  for p in paths_low)
        assert max_high >= max_low

    def test_effort_labels(self):
        assert effort_label(85.0)  == "LOW"
        assert effort_label(60.0)  == "MEDIUM"
        assert effort_label(30.0)  == "HIGH"
        assert effort_label(80.0)  == "LOW"
        assert effort_label(50.0)  == "MEDIUM"
        assert effort_label(49.9)  == "HIGH"


# ── Engine tests ──────────────────────────────────────────────────────────

class TestEngine:
    def test_analyze_returns_paths(self, simple_graph):
        report = AnalysisEngine(simple_graph).analyze()
        assert len(report.paths) > 0

    def test_top_n_respected(self, simple_graph):
        report = AnalysisEngine(simple_graph).analyze(top_n=2)
        assert len(report.paths) <= 2

    def test_paths_are_ranked_descending(self, simple_graph):
        report = AnalysisEngine(simple_graph).analyze()
        scores = [p.score for p in report.paths]
        assert scores == sorted(scores, reverse=True)

    def test_filter_type_escalation(self, simple_graph):
        report = AnalysisEngine(simple_graph).analyze(path_type="escalation")
        for p in report.paths:
            assert p.path_type == "escalation"

    def test_graph_stats_in_report(self, simple_graph):
        report = AnalysisEngine(simple_graph).analyze()
        assert "nodes" in report.graph_stats

    def test_report_to_dict(self, simple_graph):
        report = AnalysisEngine(simple_graph).analyze()
        d = report.to_dict(simple_graph)
        assert "paths" in d
        assert "stats" in d

    def test_ranks_are_sequential(self, simple_graph):
        report = AnalysisEngine(simple_graph).analyze()
        for i, p in enumerate(report.paths, 1):
            assert p.rank == i

    def test_empty_graph_no_crash(self):
        g = AttackGraph()
        report = AnalysisEngine(g).analyze()
        assert report.paths == []


# ── Validator tests ───────────────────────────────────────────────────────

class TestValidator:
    VALID = {
        "nodes": [
            {"id": "a", "type": "network"},
            {"id": "b", "type": "host"},
        ],
        "edges": [
            {"from": "a", "to": "b", "edge_type": "network_access"}
        ],
    }

    def test_valid_data_passes(self):
        ok, errs = validate(self.VALID)
        assert ok, errs

    def test_missing_nodes_key(self):
        ok, errs = validate({"edges": []})
        assert not ok
        assert any("nodes" in e for e in errs)

    def test_missing_edges_key(self):
        ok, errs = validate({"nodes": []})
        assert not ok
        assert any("edges" in e for e in errs)

    def test_unknown_node_type(self):
        data = {"nodes": [{"id": "x", "type": "spaceship"}], "edges": []}
        ok, errs = validate(data)
        assert not ok

    def test_edge_references_missing_node(self):
        data = {
            "nodes": [{"id": "a", "type": "network"}],
            "edges": [{"from": "a", "to": "ghost", "edge_type": "network_access"}],
        }
        ok, errs = validate(data)
        assert not ok

    def test_invalid_cvss_range(self):
        data = {"nodes": [{"id": "v", "type": "vulnerability", "cvss": 11.0}], "edges": []}
        ok, errs = validate(data)
        assert not ok

    def test_valid_cvss_boundary(self):
        data = {"nodes": [{"id": "v", "type": "vulnerability", "cvss": 10.0}], "edges": []}
        ok, errs = validate(data)
        assert ok, errs

    def test_validate_file_not_found(self):
        ok, errs = validate_file("/nonexistent/path.json")
        assert not ok
        assert any("not found" in e.lower() for e in errs)

    def test_validate_file_valid(self, webapp_json_path):
        ok, errs = validate_file(webapp_json_path)
        assert ok, errs

    def test_validate_ad_example(self, ad_json_path):
        ok, errs = validate_file(ad_json_path)
        assert ok, errs

    def test_malformed_json(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        ok, errs = validate_file(str(bad))
        assert not ok
        assert any("parse" in e.lower() or "json" in e.lower() for e in errs)


# ── Renderer tests ────────────────────────────────────────────────────────

class TestRenderer:
    def test_dot_output_structure(self, simple_graph):
        dot = render_dot(simple_graph)
        assert "digraph RouteZero" in dot
        assert "->" in dot

    def test_dot_contains_all_nodes(self, simple_graph):
        dot = render_dot(simple_graph)
        for node_id in simple_graph.nodes:
            assert node_id in dot

    def test_render_report_no_crash(self, simple_graph, capsys):
        from routezero.output.renderer import render_report
        report = AnalysisEngine(simple_graph).analyze()
        render_report(report, simple_graph)
        out = capsys.readouterr().out
        assert "RouteZero" in out

    def test_render_stats_no_crash(self, simple_graph, capsys):
        from routezero.output.renderer import render_stats
        render_stats(simple_graph)
        out = capsys.readouterr().out
        assert "nodes" in out.lower() or "RouteZero" in out


# ── Integration tests ─────────────────────────────────────────────────────

class TestIntegration:
    def test_webapp_example_end_to_end(self, webapp_json_path):
        ok, errs = validate_file(webapp_json_path)
        assert ok, errs
        graph  = AttackGraph.load(webapp_json_path)
        report = AnalysisEngine(graph).analyze()
        assert len(report.paths) > 0
        top = report.paths[0]
        assert top.score > 0
        assert top.effort in {"LOW", "MEDIUM", "HIGH"}

    def test_ad_example_end_to_end(self, ad_json_path):
        ok, errs = validate_file(ad_json_path)
        assert ok, errs
        graph  = AttackGraph.load(ad_json_path)
        report = AnalysisEngine(graph).analyze(path_type="escalation")
        assert len(report.paths) > 0

    def test_json_export_parseable(self, webapp_json_path):
        graph  = AttackGraph.load(webapp_json_path)
        report = AnalysisEngine(graph).analyze()
        d = report.to_dict(graph)
        dumped = json.dumps(d)
        parsed = json.loads(dumped)
        assert "paths" in parsed
        assert "stats" in parsed

    def test_dot_export(self, webapp_json_path):
        graph = AttackGraph.load(webapp_json_path)
        dot   = render_dot(graph)
        assert "digraph" in dot
        assert "attacker" in dot
