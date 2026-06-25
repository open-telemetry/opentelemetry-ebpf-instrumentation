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
  * PROTOCOL = each Service's `spec.ports[].appProtocol` field (grpc/http/redis).
  * LANGUAGE = detected from the source tree under app/src/<service>/.

Usage:
  python3 fix_architecture.py            # rewrite the generated regions in place
  python3 fix_architecture.py --check    # fail (exit 1) if the doc is stale; CI mode
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

# Kubernetes `appProtocol` value -> the label shown in the doc.
PROTOCOL_DISPLAY = {"grpc": "gRPC", "http": "HTTP", "redis": "Redis"}

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
    """Per-service manifests only; infra manifests are excluded.

    Infra/support manifests are identified by the `NN-` numbered-prefix naming
    convention (`00-namespace.yaml`, `01-observability.yaml`,
    `03-obi-values.yaml`) plus `kustomization.yaml`. This matters: for example
    `01-observability.yaml` deploys the LGTM backend as a `kind: Deployment`,
    which must NOT appear as a demo service node.

    Conventions for future contributors:
      * a new application service manifest must NOT start with a digit;
      * a new infra/support manifest should keep the `NN-` prefix so it is
        filtered out here.
    A hardcoded blacklist was considered, but the prefix convention auto-handles
    future infra files without needing edits to this script.
    """
    return [
        y for y in sorted(K8S.glob("*.yaml"))
        if not y.name[0].isdigit() and y.name != "kustomization.yaml"
    ]


def manifest_services() -> set[str]:
    """Names of every `kind: Deployment` in the per-service manifests.

    Only `Deployment` is recognised. A new service must be deployed as a
    Deployment to appear in the graph; DaemonSets, StatefulSets, bare Pods, etc.
    are intentionally not matched and would be silently omitted.
    """
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


def manifest_protocols() -> dict[str, str]:
    """{service: appProtocol} from each Service's port `appProtocol` field.

    Protocol is the one fact not derivable from the wiring (the *_ADDR env vars
    only carry host:port), so each Service declares it with the standard
    Kubernetes `spec.ports[].appProtocol` field (grpc/http/redis). The first
    `name:` after `kind: Service` is the Service name; its port `appProtocol` is
    captured.
    """
    protocols: dict[str, str] = {}
    for yaml in app_manifests():
        kind = svc = None
        for line in yaml.read_text().splitlines():
            if m := re.match(r"kind:\s*(\S+)", line):
                kind, svc = m.group(1), None
            elif kind == "Service" and svc is None and (m := re.match(r"\s+name:\s*(\S+)", line)):
                svc = m.group(1)
            elif kind == "Service" and svc and (m := re.search(r"\bappProtocol:\s*(\S+)", line)):
                protocols.setdefault(svc, m.group(1))
    return protocols


def detect_language(service: str) -> tuple[str, str]:
    """(language, source-marker) for a service, detected from app/src/<service>/.

    Heuristic: the source tree is searched for build/manifest markers in priority
    order and the FIRST match wins, so a service shipping more than one marker
    (e.g. a Go service that also has a `package.json` for assets) is classified
    by the highest-priority one. Priority:

        go.mod (Go) > *.csproj (C#/.NET) > build.gradle (Java) >
        package.json (Node.js) > requirements.txt (Python) > *.py (Python)

    A service with no `app/src/<service>/` directory falls back to the Redis
    datastore label (redis-cart runs the upstream redis:alpine image, so it has
    no vendored source).
    """
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


def render_graph(services, edges, lang_of, proto_of) -> str:
    callee_port = {callee: port for _caller, callee, port in sorted(edges)}
    present = [lang for lang in LANGUAGES if lang[0] in set(lang_of.values())]

    lines = ["```mermaid", "graph TD"]
    for svc in sorted(services):
        port = callee_port.get(svc)
        label = f"{svc}<br/>:{port} {proto_of[svc]}" if port else svc
        lines.append(f'    {_node_id(svc)}["{label}"]')
    lines.append("")
    for caller, callee, _port in sorted(edges):
        lines.append(f"    {_node_id(caller)} -->|{proto_of[callee]}| {_node_id(callee)}")
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


def render_connections(edges, proto_of) -> str:
    lines = ["| Caller | Callee | Address | Protocol |", "| --- | --- | --- | --- |"]
    for caller, callee, port in sorted(edges):
        lines.append(f"| {caller} | {callee} | `{callee}:{port}` | {proto_of[callee]} |")
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

    raw_proto = manifest_protocols()
    callees = {callee for _caller, callee, _port in edges}
    missing = sorted(c for c in callees if c not in raw_proto)
    if missing:
        sys.exit(
            f"ERROR: Service(s) missing 'appProtocol': {', '.join(missing)}. "
            "Add 'appProtocol: <grpc|http|redis>' to the Service port in k8s/."
        )
    proto_of = {svc: PROTOCOL_DISPLAY.get(p, p) for svc, p in raw_proto.items()}

    detected = {svc: detect_language(svc) for svc in services}
    lang_of = {svc: lang for svc, (lang, _marker) in detected.items()}
    marker_of = {svc: marker for svc, (_lang, marker) in detected.items()}

    return {
        "graph": render_graph(services, edges, lang_of, proto_of),
        "legend": render_legend(lang_of),
        "connections": render_connections(edges, proto_of),
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
