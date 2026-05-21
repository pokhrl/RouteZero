# RouteZero

**Attack-path analysis engine for modeling vulnerability chains, privilege escalation, and lateral movement in authorized security research environments.**

RouteZero converts infrastructure and vulnerability data into directed attack graphs, then discovers and ranks realistic attack paths automatically.

>  RouteZero is intended strictly for **authorized** security testing, research environments, and CTF use.

---

## Why RouteZero?

Most offensive security tooling focuses on individual vulnerabilities.

Real-world compromise paths are rarely caused by a single bug.

RouteZero focuses on the **relationships** between:

- vulnerabilities
- hosts
- credentials
- privilege boundaries
- network access
- sensitive data

The goal is to model how smaller weaknesses combine into meaningful attack chains.

---

## Features

- Directed attack graph generation
- Multi-stage attack chain discovery
- Risk scoring engine (0–100)
- Privilege escalation analysis
- Lateral movement mapping
- Graphviz DOT export
- Rich terminal rendering
- JSON export support
- Strict schema validation
- C-based CVSS v3.1 calculator (`tools/routezero_cvss.c`)
- Modular architecture
- Comprehensive unit tests

---

## Example

```bash
routezero analyze examples/webapp_attack.json
```

```
RouteZero Attack-Path Analysis
────────────────────────────────────────────────────────────
  Nodes : 5   Edges : 4   Density : 0.2
────────────────────────────────────────────────────────────

[CRITICAL] Attack Path #1
  Score  : 92
  Effort : LOW
  Type   : escalation

  Attacker (Internet)
   ├─ network_access [low]
        App Server
      ├─ privilege_escalation [medium]
           Domain Admin Credential
         └─ data_access [low]
              Secrets Store

  Impact: Exploits CVE-2021-44228 leading to privilege escalation with sensitive data exposure.
```

---

## Installation

```bash
# Clone
git clone https://github.com/your-org/RouteZero.git
cd RouteZero

# Install
pip install -e .

# Or dependencies only
pip install -r requirements.txt
```

Requires **Python 3.8+**.

---

## Quick Start

```bash
# Validate input
routezero validate examples/webapp_attack.json

# Build graph
routezero build examples/webapp_attack.json -o graph.json

# Analyze
routezero analyze examples/webapp_attack.json

# Filter escalation paths only
routezero analyze examples/ad_escalation.json --type escalation

# Export JSON
routezero analyze examples/webapp_attack.json --json-output > results.json

# Export DOT graph
routezero build examples/webapp_attack.json -f dot -o graph.dot
```

---

## CLI Reference

### `routezero validate INPUT`
Validates schema correctness and reports detailed parsing errors.

### `routezero build INPUT [OPTIONS]`
| Option | Description |
|---|---|
| `-o, --output PATH` | Save graph output |
| `-f, --format FORMAT` | `json` \| `dot` |
| `--skip-validate` | Skip schema validation |

### `routezero analyze INPUT [OPTIONS]`
| Option | Description |
|---|---|
| `-t, --type TYPE` | `all` \| `escalation` \| `lateral` \| `exposure` |
| `-n, --top N` | Number of paths to display (default: 10) |
| `-o, --output PATH` | Save JSON results |
| `--json-output` | Print raw JSON |
| `--graph` | Treat input as pre-built graph |

### `routezero info INPUT`
Displays node counts, edge counts, graph density, and attack surface metrics.

---

## CVSS v3.1 Calculator (C tool)

```bash
# Build
gcc -o routezero_cvss tools/routezero_cvss.c -lm -Wall -Wextra

# Usage
./routezero_cvss <AV> <AC> <PR> <UI> <S> <C> <I> <A>

# Example — Log4Shell
./routezero_cvss N L N N C H H H
# => Base Score: 10.0  Severity: CRITICAL
```

Metric values follow CVSS v3.1 shorthand:
- **AV**: N(etwork) | A(djacent) | L(ocal) | P(hysical)
- **AC**: L(ow) | H(igh)
- **PR**: N(one) | L(ow) | H(igh)
- **UI**: N(one) | R(equired)
- **S**: U(nchanged) | C(hanged)
- **C/I/A**: N(one) | L(ow) | H(igh)

---

## Input Format

RouteZero consumes JSON files with `nodes` and `edges`.

```json
{
  "nodes": [
    { "id": "attacker", "type": "network", "label": "Attacker" },
    { "id": "log4shell", "type": "vulnerability", "cvss": 10.0, "cve_id": "CVE-2021-44228" },
    { "id": "app_server", "type": "host", "os": "Linux", "services": ["java"] }
  ],
  "edges": [
    { "from": "attacker",  "to": "app_server", "edge_type": "network_access", "difficulty": "low" },
    { "from": "log4shell", "to": "app_server", "edge_type": "exploits",       "difficulty": "low" }
  ]
}
```

### Node Types
`network` | `host` | `vulnerability` | `credential` | `data` | `attacker` | `external`

### Edge Types
`network_access` | `exploits` | `privilege_escalation` | `credential_use` | `lateral_movement` | `data_access`

---

## Scoring Model

Attack paths are scored **0–100** using weighted factors:

| Factor | Weight | Max Points |
|---|---|---|
| CVSS severity | avg across vulns | 40 |
| Edge types | escalation/data-access rank higher | 30 |
| Chain length | longer validated chains | 20 |
| Difficulty | low-difficulty amplifies score | multiplier |

### Effort Levels

| Score | Effort |
|---|---|
| 80+ | LOW |
| 50–79 | MEDIUM |
| <50 | HIGH |

---

## Architecture

```
routezero/
├── core/
│   ├── graph.py       # Directed attack graph (nodes, edges, traversal)
│   ├── engine.py      # Path discovery, classification, ranking
│   └── scoring.py     # Risk scoring model
├── cli/
│   └── main.py        # Click-based CLI
├── output/
│   └── renderer.py    # Terminal, JSON, DOT rendering
└── utils/
    ├── validator.py   # JSON schema validation
    └── logging.py     # Structured logger
tools/
└── routezero_cvss.c   # Standalone C CVSS v3.1 calculator
examples/
├── webapp_attack.json
└── ad_escalation.json
tests/
└── test_routezero.py  # Full pytest suite
```

---

## Testing

```bash
pytest tests/ -v
```

Includes graph, scoring, engine, validator, renderer, CLI, and integration tests.

---

## Use Cases

**Red Teaming** — Model realistic compromise paths before engagements.

**Vulnerability Chaining** — Understand how low-severity weaknesses combine into critical exposure.

**Purple Team Exercises** — Visualize attacker movement paths collaboratively.

**Security Architecture Review** — Demonstrate attack feasibility across trust boundaries.

**CTF Design** — Prototype escalation and lateral movement scenarios quickly.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for changes
4. Submit a pull request

Please keep all contributions focused on **authorized and ethical** security research.

---

## Legal

RouteZero is provided for:

- authorized penetration testing
- research environments
- educational use
- CTF exercises

**Do not use this software against systems you do not own or have explicit written permission to assess.**
