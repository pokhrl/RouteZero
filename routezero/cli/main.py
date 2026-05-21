"""
routezero/cli/main.py
Command-line interface for RouteZero.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from routezero.core.engine import AnalysisEngine
from routezero.core.graph import AttackGraph
from routezero.output.renderer import (
    render_dot, render_json, render_report, render_stats,
)
from routezero.utils.validator import validate_file


# ── Helpers ───────────────────────────────────────────────────────────────

def _load_graph(path: str, skip_validate: bool = False) -> AttackGraph:
    if not skip_validate:
        ok, errors = validate_file(path)
        if not ok:
            click.echo(click.style("Validation failed:", fg="red", bold=True))
            for err in errors:
                click.echo(f"  • {err}")
            sys.exit(1)
    return AttackGraph.load(path)


# ── CLI group ─────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version="1.0.0", prog_name="routezero")
def cli() -> None:
    """RouteZero — Attack-path analysis engine for authorized security research."""


# ── validate ──────────────────────────────────────────────────────────────

@cli.command()
@click.argument("input", type=click.Path(exists=True))
def validate(input: str) -> None:
    """Validate schema correctness of an INPUT file."""
    ok, errors = validate_file(input)
    if ok:
        click.echo(click.style("✓ Validation passed.", fg="green", bold=True))
    else:
        click.echo(click.style("✗ Validation failed:", fg="red", bold=True))
        for err in errors:
            click.echo(f"  {err}")
        sys.exit(1)


# ── build ─────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("input", type=click.Path(exists=True))
@click.option("-o", "--output", default=None, help="Save graph output to this path")
@click.option("-f", "--format", "fmt", default="json",
              type=click.Choice(["json", "dot"]), help="Output format: json | dot")
@click.option("--skip-validate", is_flag=True, help="Skip schema validation")
def build(input: str, output: str | None, fmt: str, skip_validate: bool) -> None:
    """Build an attack graph from INPUT and optionally save it."""
    graph = _load_graph(input, skip_validate)
    if fmt == "dot":
        content = render_dot(graph)
    else:
        content = json.dumps(graph.to_dict(), indent=2)

    if output:
        Path(output).write_text(content, encoding="utf-8")
        click.echo(f"Graph saved to {output}")
    else:
        click.echo(content)


# ── analyze ───────────────────────────────────────────────────────────────

@cli.command()
@click.argument("input", type=click.Path(exists=True))
@click.option("-t", "--type", "path_type", default="all",
              type=click.Choice(["all", "escalation", "lateral", "exposure"]),
              help="Filter path type")
@click.option("-n", "--top", "top_n", default=10, show_default=True,
              help="Number of paths to display")
@click.option("-o", "--output", default=None, help="Save JSON results to this path")
@click.option("--json-output", is_flag=True, help="Print raw JSON to stdout")
@click.option("--graph", "is_graph", is_flag=True,
              help="Treat INPUT as a pre-built graph file")
def analyze(
    input: str,
    path_type: str,
    top_n: int,
    output: str | None,
    json_output: bool,
    is_graph: bool,
) -> None:
    """Discover and rank attack paths in INPUT."""
    graph = _load_graph(input, skip_validate=is_graph)
    engine = AnalysisEngine(graph)
    report = engine.analyze(path_type=path_type, top_n=top_n)

    if json_output or output:
        data = json.dumps(report.to_dict(graph), indent=2)
        if output:
            Path(output).write_text(data, encoding="utf-8")
            click.echo(f"Results saved to {output}")
        else:
            click.echo(data)
    else:
        render_report(report, graph)


# ── info ──────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("input", type=click.Path(exists=True))
@click.option("--skip-validate", is_flag=True)
def info(input: str, skip_validate: bool) -> None:
    """Display graph statistics for INPUT."""
    graph = _load_graph(input, skip_validate)
    render_stats(graph)


# ── Entry point ───────────────────────────────────────────────────────────

def main() -> None:
    cli()


if __name__ == "__main__":
    main()
