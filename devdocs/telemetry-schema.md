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
```

### Pending release notes

Breaking changes the schema cannot express: the format describes the OTLP output only, has
no operation for dropping something, and says nothing about the published reference docs.
Keep them out of the block above — copying them into a `<version>` file would corrupt a
published, immutable schema.
The release owner drains this list into the release notes at release prep, and leaves the
section empty once drained.

- Removed `PrometheusConfig.Registry`. Embedders can no longer supply a custom
  Prometheus registry; Prometheus export requires a configured HTTP port.
- GenAI client span names follow `{gen_ai.operation.name} {gen_ai.request.model}`
  (retrieval: `{gen_ai.operation.name} {gen_ai.data_source.id}`), built only from the
  values emitted on the span:
  - Anthropic Messages API: `gen_ai.operation.name` changes from `message` to `chat`
    on spans and on the `gen_ai.client.*` metrics; span name `message claude-sonnet-4-6`
    becomes `chat claude-sonnet-4-6`.
  - OpenAI-compatible gateways: span name `POST /v1/chat/completions` (or `POST /*`)
    becomes `chat gpt-4o-mini`; an unrecognized endpoint becomes `_OTHER {model}`.
  - Retrieval without a data source id: `retrieval qdrant` becomes `retrieval`.
  - Anthropic and rerank spans without a request model no longer take the model from
    the response: `message claude-sonnet-4-6` becomes `chat`, `rerank rerank-v3.5`
    becomes `rerank`.
  - A GenAI span with an empty operation is named `_OTHER {model}` instead of the HTTP
    `{method} {route}` fallback, matching the emitted `_OTHER` attribute. Today's
    parsers always set an operation, so no emitted span changes.
- An Elasticsearch or OpenSearch client span that names no index or cluster is now named
  `{db.operation.name} {server.address}:{server.port}`, as the database span name convention
  defines, using the requested host (without the port the `Host` header may carry), or else the
  resolved host name, instead of the peer IP. A span whose host was neither requested nor
  resolved keeps its name.
- Database span names follow the database span name convention in more cases. A span with no
  operation is named after its target, else its `db.system.name`: `SQL`, `REDIS`, `MEMCACHED`,
  `COUCHBASE` and `AEROSPIKE` become e.g. `postgresql` (or `other_sql`), `redis`, `memcached`,
  `couchbase` and `aerospike`, and a SQL span with only a `db.namespace` is named after it. A MongoDB or
  Couchbase span with no collection uses `db.namespace` as its target (`listCollections`
  becomes `listCollections mydb`). A Couchbase SQL++ span with no operation is named after
  its target, and its `{server.address}:{server.port}` target uses the host `server.address`
  reports instead of the peer IP. Native SQL, Redis, Memcached, MongoDB, Couchbase and
  Aerospike names still never use the `{server.address}:{server.port}` target, which keeps
  today's names and their cardinality, and Redis names do not use `db.namespace`, as the Redis
  conventions require. SQL spans are still named after `db.query.summary` when it is available,
  even if that attribute is not selected for export.
- Span names now follow semconv v1.41, which also changes the `span.name` (`span_name`)
  value of span metrics for these spans:
  - GraphQL server: `GraphQL {graphql.operation.type}` becomes `{graphql.operation.type}`
    (for example `GraphQL query` becomes `query`).
  - AWS S3: `s3.{operation}` becomes `S3.{operation}`; with no operation, `s3.Operation`
    becomes `aws-api`.
  - AWS SQS: `sqs.{operation}` becomes `SQS.{operation}`, following the AWS SDK
    `Service.Operation` rule; SQS spans emit no `rpc.*` attributes, so the operation part
    matches `messaging.operation.name`.
  - ONC RPC: `{program}/{procedure}` is unchanged; reply-only spans (no captured CALL)
    become `onc_rpc` instead of `sunrpc/reply`.
- ONC RPC spans now carry `rpc.method` as `{program}/{procedure}` when the CALL was captured.
- The ONC RPC `rpc.method` value on `rpc.client.call.duration` and `rpc.server.call.duration`
  changes from the procedure number (for example `0`) to `{program}/{procedure}` (for example
  `portmapper/0`), and is omitted when no CALL was captured (previously `reply`).

## Hosting notes

`site/` is published as static files with no markdown processing, so the generated
pages under `site/docs/` are served as markdown, not HTML. They are meant to be
read rendered: on GitHub, or on the OpenTelemetry website, where OBI has a docs
section (`/docs/zero-code/obi/`) that is where these generated pages belong. The
published copies exist so the reference is fetchable at a stable URL alongside the
schema files.
