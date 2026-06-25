# Store Demo Provenance

## Upstream Source

- Repository: <https://github.com/GoogleCloudPlatform/microservices-demo>
- Tag: v0.10.5
- Commit: 16a51f8dbabc4af2c4c82f81ca6d4813888c2c34
- License: Apache License 2.0

## Curation Notes

The store demo assets in this directory are curated from the upstream
GoogleCloudPlatform/microservices-demo v0.10.5 release for OBI example use.
The upstream Apache License 2.0 text is copied into `app/LICENSE`.

OBI-specific configuration, documentation, manifests, or wrapper scripts may be
kept alongside the vendored application content in this directory. Those files
are maintained by this repository unless they explicitly state otherwise.

## Excluded Upstream Areas

The upstream release contains development, deployment, infrastructure, release,
and documentation material that is not vendored here by default. Excluded areas
include upstream CI configuration, `.deploystack/`, `docs/`, `helm-chart/`,
`istio-manifests/`, `kubernetes-manifests/`, `kustomize/`, `release/`,
`terraform/`, and any source service or generated artifact that is not
explicitly present under `examples/store-demo/app/`.

Of the twelve `src/` services in the upstream release, eleven are vendored here.
`shoppingassistantservice` is intentionally excluded: it requires external
Google Vertex AI / Gemini credentials and an AlloyDB vector store, and is not
part of the upstream default deployment, so it adds cloud dependencies without
helping demonstrate OBI's eBPF instrumentation.
