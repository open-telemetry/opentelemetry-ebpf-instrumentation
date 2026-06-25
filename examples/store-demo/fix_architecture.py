#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
"""Generate the topology sections of ARCHITECTURE.md from the k8s manifests.

The Mermaid graph, the Connections table, the language legend, and the Service
Languages table are all derived from ground truth and written into the marked
`<!-- generated:NAME -->` ... `<!-- /generated:NAME -->` regions of the doc. The
prose around those regions is left untouched.

Ground truth:
  * SERVICES = every `kind: Deployment` in the per-service manifests (k8s/).
  * EDGES    = every `*_ADDR` env var, as (caller, callee, port); the owning
               manifest is the caller, the value is "callee:port" it dials.
  * LANGUAGE = detected from the source tree under app/src/<service>/.

The only fact not in the manifests is the wire protocol, which is a function of
the callee: the frontend is reached over HTTP, redis-cart over Redis, and every
other service over gRPC (see PROTOCOL_BY_CALLEE).

Usage:
  python3 fix_architecture.py            # rewrite the generated regions in place
  python3 fix_architecture.py --check    # fail (exit 1) if the doc is stale; CI mode

stdlib only — no PyYAML — so it cannot fail on a missing dependency.
"""

import difflib
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
K8S = HERE / "k8s"
APP_SRC = HERE / "app" / "src"
DOC = HERE / "ARCHITECTURE.md"

# name: SOMETHING_ADDR  then  value: "callee:port" on the following line.
ADDR_RE = re.compile(
    r'name:\s*([A-Za-z0-9_]+_ADDR)\s*[\r\n]+\s*value:\s*"?([^"\r\n]+?)"?\s*$',
    re.MULTILINE,
)

# Protocol is the one thing not encoded in the manifests. In this demo it is a
# property of the callee: everything is gRPC except the HTTP frontend and the
# Redis datastore. New non-gRPC callees must be added here.
PROTOCOL_BY_CALLEE = {"frontend": "HTTP", "redis-cart": "Redis"}
DEFAULT_PROTOCOL = "gRPC"

# Language -> (mermaid classDef name, fill, stroke, text) in legend/classDef order.
LANGUAGES = [
    ("Go", "go", "darkturquoise", "teal", "black"),
    ("Python", "python", "gold", "goldenrod", "black"),
    ("Node.js", "nodejs", "forestgreen", "darkgreen", "white"),
    ("C# / .NET", "dotnet", "rebeccapurple", "indigo", "white"),
    ("Java", "java", "darkorange", "chocolate", "black"),
    ("Redis (datastore)", "datastore", "firebrick", "darkred", "white"),
]


def app_manifests() -> list[Path]:
    """Per-service manifests only: skip numbered infra files and kustomization."""
    return [
        y for y in sorted(K8S.glob("*.yaml"))
        if not y.name[0].isdigit() and y.name != "kustomization.yaml"
    ]


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


def manifest_edges() -> set[tuple[str, str, str]]:
    """{(caller, callee, port)} from every *_ADDR env var."""
    edges = set()
    for yaml in app_manifests():
        caller = yaml.stem  # one service per manifest; filename == caller
        for _name, value in ADDR_RE.findall(yaml.read_text()):
            callee, _, port = value.strip().rpartition(":")
            edges.add((caller, callee, port))
    return edges


def detect_language(service: str) -> tuple[str, str]:
    """(language, source-marker) for a service, from its app/src/ source tree."""
    base = APP_SRC / service
    if not base.is_dir():
        if "redis" in service:
            return "Redis (datastore)", "upstream `redis:alpine` image"
        return "Unknown", ""

    def first(pattern: str):
        return next(iter(sorted(base.rglob(pattern))), None)

    if first("go.mod"):
        return "Go", "`go.mod`"
    csproj = first("*.csproj")
    if csproj:
        return "C# / .NET", f"`{csproj.name}`"
    if first("build.gradle"):
        return "Java", "`build.gradle`"
    if first("package.json"):
        return "Node.js", "`package.json`"
    if first("requirements.txt"):
        return "Python", "`requirements.txt`"
    py = first("*.py")
    if py:
        return "Python", f"`{py.name}`"
    return "Unknown", ""


def _node_id(service: str) -> str:
    """Mermaid-safe node id (hyphens are not valid in flowchart ids)."""
    return service.replace("-", "_")


def _protocol(callee: str) -> str:
    return PROTOCOL_BY_CALLEE.get(callee, DEFAULT_PROTOCOL)


def render_graph(services, edges, lang_of) -> str:
    callee_port = {callee: port for _caller, callee, port in edges}
    present = [lang for lang in LANGUAGES if lang[0] in set(lang_of.values())]

    lines = ["```mermaid", "graph TD"]
    for svc in sorted(services):
        port = callee_port.get(svc)
        label = f"{svc}<br/>:{port} {_protocol(svc)}" if port else svc
        lines.append(f'    {_node_id(svc)}["{label}"]')
    lines.append("")
    for caller, callee, _port in sorted(edges):
        lines.append(f"    {_node_id(caller)} -->|{_protocol(callee)}| {_node_id(callee)}")
    lines.append("")
    for name, cls, fill, stroke, text in present:
        lines.append(f"    classDef {cls} fill:{fill},stroke:{stroke},color:{text};")
    lines.append("")
    for name, cls, *_ in present:
        members = sorted(_node_id(s) for s in services if lang_of[s] == name)
        lines.append(f"    class {','.join(members)} {cls};")
    lines.append("```")
    return "\n".join(lines)


def render_legend(lang_of) -> str:
    present = [lang for lang in LANGUAGES if lang[0] in set(lang_of.values())]
    parts = [f'<span style="color:{fill}">■</span> {name}'
             for name, _cls, fill, _stroke, _text in present]
    return "**Language legend:** " + " &nbsp;\n".join(parts)


def render_connections(edges) -> str:
    lines = ["| Caller | Callee | Address | Protocol |", "| --- | --- | --- | --- |"]
    for caller, callee, port in sorted(edges):
        lines.append(f"| {caller} | {callee} | `{callee}:{port}` | {_protocol(callee)} |")
    return "\n".join(lines)


def render_languages(services, lang_of, marker_of) -> str:
    lines = ["| Service | Language | Source marker |", "| --- | --- | --- |"]
    for svc in sorted(services):
        lines.append(f"| {svc} | {lang_of[svc]} | {marker_of[svc]} |")
    return "\n".join(lines)


def render_regions() -> dict[str, str]:
    services = manifest_services()
    edges = manifest_edges()
    if not services or not edges:
        sys.exit("ERROR: no services/edges found in manifests; check k8s/ path.")

    detected = {svc: detect_language(svc) for svc in services}
    lang_of = {svc: lang for svc, (lang, _marker) in detected.items()}
    marker_of = {svc: marker for svc, (_lang, marker) in detected.items()}

    return {
        "graph": render_graph(services, edges, lang_of),
        "legend": render_legend(lang_of),
        "connections": render_connections(edges),
        "languages": render_languages(services, lang_of, marker_of),
    }


def apply(text: str, regions: dict[str, str]) -> str:
    for name, content in regions.items():
        pattern = re.compile(
            rf"(<!-- generated:{name} -->\n).*?(\n<!-- /generated:{name} -->)",
            re.DOTALL,
        )
        text, n = pattern.subn(lambda m: m.group(1) + content + m.group(2), text)
        if n == 0:
            sys.exit(f"ERROR: missing '<!-- generated:{name} -->' markers in {DOC.name}")
    return text


def main(argv: list[str]) -> int:
    check = "--check" in argv[1:]
    current = DOC.read_text()
    updated = apply(current, render_regions())

    if not check:
        if updated != current:
            DOC.write_text(updated)
            print(f"Updated {DOC.name} from the manifests.")
        else:
            print(f"{DOC.name} already in sync.")
        return 0

    if updated == current:
        print(f"{DOC.name} is in sync with the manifests.")
        return 0
    diff = difflib.unified_diff(
        current.splitlines(keepends=True), updated.splitlines(keepends=True),
        fromfile=f"{DOC.name} (committed)", tofile=f"{DOC.name} (from manifests)",
    )
    sys.stderr.writelines(diff)
    print(f"\n{DOC.name} is stale. Run: python3 examples/store-demo/fix_architecture.py",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
