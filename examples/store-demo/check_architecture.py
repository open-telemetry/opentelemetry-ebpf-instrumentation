#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
"""Verify ARCHITECTURE.md matches the deployed manifests.

Ground truth is the k8s manifests:
  * SERVICES = every `kind: Deployment` declared in the per-service manifests.
  * EDGES    = every `*_ADDR` env var, as (caller, "host:port"); the owning
               manifest is the caller, the value is what it dials.

ARCHITECTURE.md describes the same system three times — a Mermaid graph, a
Connections table, and a Service Languages table. This script checks all three
against the manifests so none of them can silently drift:

  1. Connections-table edges            == manifest EDGES
  2. Connections-table participants     == manifest SERVICES
  3. Service-Languages-table services   == manifest SERVICES
  4. Mermaid declared nodes             == manifest SERVICES
  5. Mermaid arrows (caller->callee)    == Connections-table (Caller, Callee)
  6. Mermaid node port+protocol labels  == Connections-table (Callee, port, protocol)

Checks 2-4 are what catch a deleted/added manifest (e.g. removing a leaf
service like adservice that owns no edges) and a deleted Mermaid node line.
Check 6 keeps the `:port protocol` text inside each Mermaid node label aligned
with the table, so editing one without the other fails.

stdlib only — no PyYAML — so it cannot fail on a missing dependency.
"""

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
K8S = HERE / "k8s"
DOC = HERE / "ARCHITECTURE.md"

# name: SOMETHING_ADDR  then  value: "host:port" on the following line.
ADDR_RE = re.compile(
    r'name:\s*([A-Za-z0-9_]+_ADDR)\s*[\r\n]+\s*value:\s*"?([^"\r\n]+?)"?\s*$',
    re.MULTILINE,
)
# A declared Mermaid node:  id["label ... "]
NODE_RE = re.compile(r'^\s*([A-Za-z0-9_-]+)\["([^"]*)"\]')
# A Mermaid arrow:  src -->|label| dst   (label optional)
ARROW_RE = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*-->\s*(?:\|[^|]*\|)?\s*([A-Za-z0-9_-]+)')
# The ":port protocol" tail of a node label, e.g. ":3550 gRPC".
PORT_PROTO_RE = re.compile(r':(\d+)\s+(\S+)')


def app_manifests() -> list[Path]:
    """Per-service manifests only: skip numbered infra files and kustomization."""
    out = []
    for yaml in sorted(K8S.glob("*.yaml")):
        if yaml.name[0].isdigit() or yaml.name == "kustomization.yaml":
            continue
        out.append(yaml)
    return out


def manifest_services() -> set[str]:
    """Names of every Deployment declared in the per-service manifests."""
    services = set()
    for yaml in app_manifests():
        expect_name = False
        for line in yaml.read_text().splitlines():
            if re.match(r"\s*kind:\s*Deployment\s*$", line):
                expect_name = True
            elif expect_name:
                m = re.match(r"\s+name:\s*(\S+)", line)
                if m:
                    services.add(m.group(1))
                    expect_name = False
    return services


def manifest_edges() -> set[tuple[str, str]]:
    """{(caller, "host:port")} from every *_ADDR env var."""
    edges = set()
    for yaml in app_manifests():
        caller = yaml.stem  # one service per manifest; filename == caller
        for _name, value in ADDR_RE.findall(yaml.read_text()):
            edges.add((caller, value.strip()))
    return edges


def _table_rows(section: str) -> list[list[str]]:
    """Cell lists for each data row of the markdown table under `## <section>`."""
    rows = []
    in_section = False
    for line in DOC.read_text().splitlines():
        if line.startswith("## "):
            in_section = line.strip() == f"## {section}"
            continue
        if not in_section or not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells or cells[0] == "" or set(cells[0]) <= {"-", ":"}:  # separator
            continue
        rows.append(cells)
    return rows


def connections() -> list[tuple[str, str, str, str]]:
    """(caller, callee, address, protocol) for each Connections-table data row."""
    out = []
    for cells in _table_rows("Connections"):
        if len(cells) < 4 or cells[0] == "Caller":  # header
            continue
        out.append((cells[0], cells[1], cells[2].strip("`").strip(), cells[3]))
    return out


def doc_language_services() -> set[str]:
    """Services listed in the Service Languages table."""
    services = set()
    for cells in _table_rows("Service Languages"):
        if cells[0] == "Service":  # header
            continue
        services.add(cells[0])
    return services


def _mermaid_block() -> list[str]:
    block, inside = [], False
    for line in DOC.read_text().splitlines():
        if line.strip().startswith("```mermaid"):
            inside = True
            continue
        if inside and line.strip() == "```":
            break
        if inside:
            block.append(line)
    return block


def mermaid_parse() -> tuple[set[str], set[tuple[str, str]], set[tuple[str, str, str]]]:
    """Parse the Mermaid block once into (nodes, arrows, port/protocol attrs).

    Arrows are resolved against the node-id->service map after the loop, so a
    node referenced before its declaration is still handled. Nodes without a
    port (e.g. the loadgenerator client) contribute no attrs, mirroring the
    table: a service only has a port where it is a callee.
    """
    id_to_service: dict[str, str] = {}
    nodes: set[str] = set()
    attrs: set[tuple[str, str, str]] = set()
    raw_arrows: list[tuple[str, str]] = []
    for line in _mermaid_block():
        node = NODE_RE.match(line)
        if node:
            head, _, detail = node.group(2).partition("<br/>")
            svc = head.strip()
            id_to_service[node.group(1)] = svc
            nodes.add(svc)
            pp = PORT_PROTO_RE.search(detail)
            if pp:
                attrs.add((svc, pp.group(1), pp.group(2)))
            continue
        arrow = ARROW_RE.match(line)
        if arrow:
            raw_arrows.append((arrow.group(1), arrow.group(2)))
    arrows = {
        (id_to_service.get(src, src), id_to_service.get(dst, dst))
        for src, dst in raw_arrows
    }
    return nodes, arrows, attrs


def _report(label: str, expected: set, actual: set, exp_name: str, act_name: str) -> bool:
    """Print a pass/fail line; on failure show the symmetric difference."""
    if expected == actual:
        print(f"OK:   {label} ({len(expected)} items)")
        return True
    print(f"FAIL: {label}", file=sys.stderr)
    for item in sorted(expected - actual):
        print(f"        in {exp_name} but not {act_name}: {item}", file=sys.stderr)
    for item in sorted(actual - expected):
        print(f"        in {act_name} but not {exp_name}: {item}", file=sys.stderr)
    return False


def main() -> int:
    services = manifest_services()
    edges = manifest_edges()
    if not services or not edges:
        print("ERROR: no services/edges found in manifests; check k8s/ path.", file=sys.stderr)
        return 2

    conns = connections()
    table_edges = {(caller, addr) for caller, _callee, addr, _proto in conns}
    table_pairs = {(caller, callee) for caller, callee, _addr, _proto in conns}
    table_attrs = {(callee, addr.split(":")[-1], proto) for _caller, callee, addr, proto in conns}
    table_services = {svc for caller, callee, *_ in conns for svc in (caller, callee)}

    nodes, arrows, node_attrs = mermaid_parse()

    ok = True
    ok &= _report("Connections-table edges vs manifest *_ADDR vars",
                  edges, table_edges, "manifests", "table")
    ok &= _report("Connections-table services vs manifest Deployments",
                  services, table_services, "manifests", "table")
    ok &= _report("Service-Languages-table services vs manifest Deployments",
                  services, doc_language_services(), "manifests", "languages-table")
    ok &= _report("Mermaid nodes vs manifest Deployments",
                  services, nodes, "manifests", "mermaid")
    ok &= _report("Mermaid arrows vs Connections-table pairs",
                  table_pairs, arrows, "table", "mermaid")
    ok &= _report("Mermaid node port+protocol vs Connections-table",
                  table_attrs, node_attrs, "table", "mermaid")

    if ok:
        print("\nARCHITECTURE.md is in sync with the manifests.")
        return 0
    print("\nUpdate examples/store-demo/ARCHITECTURE.md (or the manifests) to reconcile.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
