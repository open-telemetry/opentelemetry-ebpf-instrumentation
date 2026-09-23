# Published OBI telemetry schema

This directory is the source for OBI's published [OpenTelemetry Telemetry
Schema](https://opentelemetry.io/docs/specs/otel/schemas/) files. It is deployed
verbatim to GitHub Pages by `.github/workflows/publish-schemas.yml`, so the file

```text
site/schemas/obi/<version>
```

is served at

```text
https://open-telemetry.github.io/opentelemetry-ebpf-instrumentation/schemas/obi/<version>
```

which is the `schema_url` OBI stamps onto its OTLP telemetry (see
`pkg/export/attributes/names/schema_version.go`, `OBISchemaURL`).

## Rules

- **One file per release**, named by the OBI release version, no extension.
- **Files are immutable once released** — a published `schema_url` is a
  permanent identity. Never edit a released file; add a new version instead.
- The `versions:` block records the transformations (attribute/metric renames)
  between versions, newest first. The first release is an empty baseline.
- The `schema_url:` inside each file MUST equal its served URL. `make
  check-schema-files` enforces this.

## Releasing a new version

Version management is release-driven. The version comes from `versions.yaml`
(the OBI release version), and `make prerelease` runs `make generate-schema-next`
automatically, which:

- cuts `site/schemas/obi/<version>` (previous file plus a new, empty `<version>:`
  entry on top),
- regenerates the reference docs under `site/docs/`, and
- bumps `OBISchemaURL` in `pkg/export/attributes/names/schema_version.go` and the
  `schema_url` in `schemas/obi/manifest.yaml` to `<version>`.

These changes are part of the release-prep commit; on merge to `main` the file is
deployed by `publish-schemas.yml`. `make check-schema-files` (run in CI) enforces
that the emitted `OBISchemaURL` and the manifest both name the `versions.yaml`
version and that a schema file for that version is actually published.

**If telemetry changed this release** (an attribute or metric was renamed), add
the transformation entries by hand under the new `<version>:` block before
committing, draining "Pending transformations" below. Drain "Pending release
notes" into the release notes at the same time: those are telemetry changes the
schema format cannot express, so nothing else will surface them. E.g.:

```yaml
versions:
  <version>:
    all:
      changes:
        - rename_attributes:
            attribute_map:
              old.attribute.name: new.attribute.name
    metrics:
      changes:
        - rename_metrics:
            old_metric_name: new_metric_name
```

Released files are immutable — never edit a `<version>` file once it has shipped;
only add new ones.

### Pending transformations

A change that renames emitted telemetry lands before the version that ships it
exists, so it records the transformation here and the release owner drains this list
into the new `<version>:` block at release prep. Leave the section empty once drained.

A removal goes under "Pending release notes" below instead: the format has
`rename_attributes` and `rename_metrics` and no operation for dropping something.

```yaml
all:
  changes:
    - rename_attributes:
        attribute_map:
          obi.error: error.type
```

### Pending release notes

Breaking changes the schema cannot express: the format describes the OTLP output only, has
no operation for dropping something, and says nothing about the published reference docs.
Keep them out of the block above — copying them into a `<version>` file would corrupt a
published, immutable schema.
The release owner drains this list into the release notes at release prep, and leaves the
section empty once drained.

- The Prometheus `traces_host_info` metric labels the host id `host_id` instead of
  `cloud_host_id`, matching the `host.id` the OTLP exporter reports and the `host_id`
  that `target_info` already carried. Dashboards selecting
  `traces_host_info{cloud_host_id=...}` must be updated. A component vendoring OBI that
  assigns to `prom.CloudHostIDKey` keeps its own label name.
- The OTLP span metrics (`traces.span.metrics.*`, and the `traces_spanmetrics_*` names the
  legacy feature emits over OTLP) no longer carry the `host.id` data point attribute. The
  value is unchanged on the resource, so OTLP consumers reading resource attributes lose
  nothing and `target_info` still carries `host_id`. What changes is that a consumer
  flattening OTLP to Prometheus no longer gets `host_id` as a per-series label on the span
  metrics themselves. OBI's own Prometheus exporter is unaffected: its span metrics never
  carried a host id label.
- OBI's own `OTEL_RESOURCE_ATTRIBUTES` now ranks below the metadata OBI resolved for a
  target, and merges per key rather than per variable. Deployments that set a key the
  resolved metadata also provides — `k8s.pod.name`, say — stop seeing the agent's value
  override the target's, and targets that declare `OTEL_RESOURCE_ATTRIBUTES` of their own
  no longer discard the whole deployment-wide layer, so they start carrying the agent's
  other keys. The target's own declaration still wins over both for the keys it declares.
- `span.obi.http.client` keeps its id but no longer declares the JSON-RPC attributes
  (`rpc.system.name`, `rpc.method`, `rpc.method_original`, `rpc.response.status_code`,
  `jsonrpc.protocol.version`, `jsonrpc.request.id`); they move to the new
  `span.obi.jsonrpc.client`. Nothing changes in the emitted telemetry.
- Five span group ids are replaced by per-system ones:
  `span.obi.messaging.{producer,consumer,client}` become
  `span.obi.messaging.<broker>.{producer,consumer,client}`, and
  `span.obi.rpc.{client,server}` become `span.obi.rpc.{grpc,onc_rpc}.{client,server}`.
  No emitted attribute changes, but a link into `site/docs/spans.md` anchored on
  one of the old ids no longer resolves.

## Hosting notes

`site/` is published as static files with no markdown processing, so the generated
pages under `site/docs/` are served as markdown, not HTML. They are meant to be
read rendered: on GitHub, or on the OpenTelemetry website, where OBI has a docs
section (`/docs/zero-code/obi/`) that is where these generated pages belong. The
published copies exist so the reference is fetchable at a stable URL alongside the
schema files.
