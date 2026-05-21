"""
routezero/utils/validator.py
JSON schema validation for RouteZero input files.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

VALID_NODE_TYPES  = {"network", "host", "vulnerability", "credential", "data", "attacker", "external"}
VALID_EDGE_TYPES  = {"network_access", "exploits", "privilege_escalation",
                     "credential_use", "lateral_movement", "data_access"}
VALID_DIFFICULTIES = {"low", "medium", "high"}


def _validate_node(raw: Any, idx: int) -> List[str]:
    errs = []
    if not isinstance(raw, dict):
        return [f"Node[{idx}] must be a JSON object"]
    if "id" not in raw:
        errs.append(f"Node[{idx}] missing required field 'id'")
    if "type" not in raw:
        errs.append(f"Node[{idx}] missing required field 'type'")
    elif raw["type"] not in VALID_NODE_TYPES:
        errs.append(
            f"Node[{idx}] ({raw.get('id','?')}) has unknown type '{raw['type']}'. "
            f"Valid: {sorted(VALID_NODE_TYPES)}"
        )
    if "cvss" in raw:
        try:
            v = float(raw["cvss"])
            if not (0.0 <= v <= 10.0):
                errs.append(f"Node[{idx}] cvss must be 0.0–10.0, got {v}")
        except (TypeError, ValueError):
            errs.append(f"Node[{idx}] cvss must be a number")
    return errs


def _validate_edge(raw: Any, idx: int, node_ids: set) -> List[str]:
    errs = []
    if not isinstance(raw, dict):
        return [f"Edge[{idx}] must be a JSON object"]
    for field in ("from", "to"):
        if field not in raw:
            errs.append(f"Edge[{idx}] missing required field '{field}'")
        elif raw[field] not in node_ids:
            errs.append(
                f"Edge[{idx}] references unknown node '{raw[field]}' in field '{field}'"
            )
    if "edge_type" in raw and raw["edge_type"] not in VALID_EDGE_TYPES:
        errs.append(
            f"Edge[{idx}] has unknown edge_type '{raw['edge_type']}'. "
            f"Valid: {sorted(VALID_EDGE_TYPES)}"
        )
    if "difficulty" in raw and raw["difficulty"].lower() not in VALID_DIFFICULTIES:
        errs.append(
            f"Edge[{idx}] has unknown difficulty '{raw['difficulty']}'. "
            f"Valid: {sorted(VALID_DIFFICULTIES)}"
        )
    return errs


def validate(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate raw parsed JSON. Returns (ok, errors)."""
    errors: List[str] = []

    if "nodes" not in data:
        errors.append("Top-level key 'nodes' is required")
    if "edges" not in data:
        errors.append("Top-level key 'edges' is required")
    if errors:
        return False, errors

    if not isinstance(data["nodes"], list):
        errors.append("'nodes' must be a JSON array")
    if not isinstance(data["edges"], list):
        errors.append("'edges' must be a JSON array")
    if errors:
        return False, errors

    for i, node in enumerate(data["nodes"]):
        errors.extend(_validate_node(node, i))

    node_ids = {n["id"] for n in data["nodes"] if isinstance(n, dict) and "id" in n}
    for i, edge in enumerate(data["edges"]):
        errors.extend(_validate_edge(edge, i, node_ids))

    return len(errors) == 0, errors


def validate_file(path: str) -> Tuple[bool, List[str]]:
    p = Path(path)
    if not p.exists():
        return False, [f"File not found: {path}"]
    try:
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        return False, [f"JSON parse error: {exc}"]
    return validate(data)
