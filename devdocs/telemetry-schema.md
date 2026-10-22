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

- **One file per stable release**, named by the OBI release version, no extension.
  Prereleases retain the previous published stable schema. Schema consumers
  require `MAJOR.MINOR.PATCH` identifiers in schema URLs and version keys.
- Build metadata in release tags is omitted from the schema identity:
  `v1.0.0+build.123` uses the `1.0.0` schema, and `v1.0.0-rc.1+build.123`
  retains the previous published stable schema.
- **Files are immutable once released** — a published `schema_url` is a
  permanent identity. Never edit a released file; add a new version instead.
- The `versions:` block records the transformations (attribute/metric renames)
  between versions, newest first. The first release is an empty baseline.
- The `schema_url:` inside each file MUST equal its served URL. `make
  check-schema-files` enforces this.

## Releasing a new version

Version management is release-driven. The version comes from `versions.yaml`
(the OBI release version), and `make prerelease` runs `make generate-schema-next`
automatically. For stable releases, it:

- cuts `site/schemas/obi/<version>` (previous file plus a new, empty `<version>:`
  entry on top),
- regenerates the reference docs under `site/docs/`, and
- bumps `OBISchemaURL` in `pkg/export/attributes/names/schema_version.go` and the
  `schema_url` in `schemas/obi/manifest.yaml` to `<version>`.

These changes are part of the release-prep commit; on merge to `main` the file is
deployed by `publish-schemas.yml`. `make check-schema-files` (run in CI) enforces
that the emitted `OBISchemaURL` and the manifest both name the `versions.yaml`
version and that a schema file for that version is actually published. For
prereleases, generation leaves the published schemas and both URLs unchanged;
validation requires the URLs to agree and identify a published stable schema.
Reference docs are still regenerated for prereleases.

Keep pending transformations through the RC phase and apply them when preparing
the stable release. RC telemetry must remain compatible with the retained schema;
if an RC needs telemetry renames, its schema identity must be decided before
publication.

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
metrics:
  changes:
    - rename_attributes:
        attribute_map:
          http.route: url.template
        apply_to_metrics:
          - http.client.request.duration
          - http.client.request.body.size
          - http.client.response.body.size
```

### Pending release notes

Breaking changes the schema cannot express: the format describes the OTLP output only, has
no operation for dropping something, and says nothing about the published reference docs.
Keep them out of the block above — copying them into a `<version>` file would corrupt a
published, immutable schema.
The release owner drains this list into the release notes at release prep, and leaves the
section empty once drained.

- A SQL++ span from a server other than Couchbase (`db.system.name` `other_sql`) that names no
  collection or bucket is named `{db.operation.name}`, like other SQL spans, instead of
  `{db.operation.name} {server.address}:{server.port}`. Couchbase SQL++ spans are unchanged.
- The HTTP client metrics (`http.client.request.duration`, `http.client.request.body.size`,
  `http.client.response.body.size`) carry the route as `url.template` instead of `http.route`,
  with the same value; the transformation above records it for OTLP. The Prometheus exporter
  label changes from `http_route` to `url_template` on `http_client_request_duration_seconds`,
  `http_client_request_body_size_bytes` and `http_client_response_body_size_bytes`, and an
  `attributes.select` entry naming `http.route` for these metrics must name `url.template`.
  As in semconv, `url.template` is on by default on the two body-size metrics but opt-in on
  `http.client.request.duration`, so client duration series no longer split by route unless
  `url.template` is selected.
- The HTTP metrics no longer offer `url.path`, and the HTTP server metrics and
  `rpc.server.call.duration` no longer offer `client.address`, following the semantic
  conventions, which exclude these high-cardinality attributes from metrics. Both were opt-in,
  so only an `attributes.select` that included them changes. `url.path` can still be used in
  attribute filters, and the spans keep both attributes.
- HTTP client spans no longer carry `url.query`; the scrubbed query string remains part of
  `url.full`. HTTP server spans keep `url.query`.
- The span reference (`site/docs/spans.md`) documents every span's name. The emitted
  telemetry is unchanged.
- The trace resource no longer carries `otel.scope.name`. Spans now carry the instrumentation
  scope itself (`go.opentelemetry.io/obi`, the OBI version and the schema URL), so resource
  filters on `otel.scope.name` must use the instrumentation scope name instead. Exporters to
  formats without a scope (Jaeger, Zipkin) still report `otel.scope.name` on each span. All
  OBI metric scopes now carry the OBI version and the schema URL.

## Hosting notes

`site/` is published as static files with no markdown processing, so the generated
pages under `site/docs/` are served as markdown, not HTML. They are meant to be
read rendered: on GitHub, or on the OpenTelemetry website, where OBI has a docs
section (`/docs/zero-code/obi/`) that is where these generated pages belong. The
published copies exist so the reference is fetchable at a stable URL alongside the
schema files.
