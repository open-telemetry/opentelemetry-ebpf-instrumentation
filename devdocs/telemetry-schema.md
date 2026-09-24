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
- The pinned `traces_ctx_v1` map is no longer populated by default. It is what an external
  reader correlates against, so a profiler doing trace-profile correlation stops matching
  samples to spans until `ebpf.populate_trace_context` (`OTEL_EBPF_BPF_POPULATE_TRACE_CONTEXT`)
  is set to `true`. OBI's own readers, the log enricher and the Node.js manual span bridge,
  turn population on by themselves and are unaffected.
- Go channel span links may be emitted less often. Handoff correlation resolves the sender
  from the per-goroutine protocol maps and falls back to `traces_ctx_v1`, so a handoff that
  relied on that fallback now emits no link. Handoffs whose sender is covered by a protocol
  map are unaffected. `ebpf.populate_trace_context: true` restores the fallback.

- A span attribute OBI parses but could not determine is no longer emitted as an empty
  string. It covers every such attribute the span exporter appends, among them
  `server.address`, `client.address`, `service.peer.name`, `url.scheme`, `url.full`,
  `db.namespace`, `db.collection.name`, `db.query.text`, `elasticsearch.node.name`,
  `graphql.operation.name`, `graphql.document`, `aws.s3.key`, `aws.s3.bucket`,
  `aws.sqs.queue.url`, `aws.request.id`, `aws.extended_request_id`, `cloud.region`,
  `dns.question.name`, `messaging.message.id`, `messaging.client.id` on MQTT and NATS spans,
  `messaging.destination.name` on the AWS SQS and SNS spans, `db.response.status_code`,
  `rpc.method` on SNS, and the `gen_ai.*` model, response-id, conversation-id, provider-name
  and message-payload attributes. A consumer selecting on the presence of one of these sees
  it absent where it previously carried `""`.
  Some are absent far more often than their names suggest: `elasticsearch.node.name` comes
  from a header only Elastic Cloud sets, `aws.s3.key` is empty for every bucket-level call,
  and `aws.extended_request_id` is empty on every SQS span.
- `service.peer.name` disappears only where OBI resolved no name for the other end. The name
  resolver falls back to the peer IP, so this is rare — but a deployment that disables the
  resolver, or a component vendoring OBI that builds a pipeline without it, loses the
  attribute on every client span outside Kubernetes.
- Metric labels are unchanged, so a metric series still carries `server.address=""` where the
  span now omits it. Anything joining spans to RED metrics on these keys must account for the
  difference until the metric path follows.
- Attributes an application sets on a manual span are untouched, including ones it
  deliberately sets to an empty string. Resource attributes are unchanged.
- Spans no longer carry `service.peer.name`, `http.request.body.size`,
  `http.response.body.size` or `obi.http.response.observed` by default. All four are
  now `opt_in` and are emitted again when named in `attributes.select.traces.include`.
  OBI's own service-graph and span metrics are computed before trace export and are
  unaffected, but tools that build service graphs from spans downstream — the collector
  `servicegraph` connector's `virtual_node_peer_attributes`, or Tempo's metrics-generator
  `peer_attributes` — stop naming uninstrumented peers such as databases and external
  hosts unless `service.peer.name` is included. A collector embedding OBI that passes its
  own attribute set to `TraceAttributesSelector` stops receiving all four the same way.
- `span.obi.http.server` keeps its id but no longer declares the GraphQL, MCP, GenAI
  tool and JSON-RPC attributes. They move to the new `span.obi.graphql.server`,
  `span.obi.mcp.server` and `span.obi.jsonrpc.server`, which extend it. Likewise
  `span.obi.db.client` no longer covers SQL clients, which move to the new
  `span.obi.db.sql.client`, together with `db.query.summary`, which only the SQL client
  emits. Nothing else changes in the emitted telemetry.
- `span.obi.http.server`, `span.obi.http.client` and `span.obi.db.sql.client` are now
  `stable`, and `span.obi.rpc.grpc.client` and `span.obi.rpc.grpc.server` are now
  `release_candidate`. `span.metrics.skip` is declared `opt_in` instead of
  `conditionally_required` on every span group; it is still emitted only when a
  span-metrics feature is enabled.
- In the new protocol server groups, attributes that the old `span.obi.http.server`
  declared as conditional on the protocol being identified are now `required`
  (`mcp.method.name`, `rpc.system.name`, `rpc.method`), since group membership already
  implies it, and `gen_ai.operation.name` on MCP spans is conditional on a tool call,
  the only MCP operation that sets it. These correct the declarations; the emitted
  telemetry is unchanged.

## Hosting notes

`site/` is published as static files with no markdown processing, so the generated
pages under `site/docs/` are served as markdown, not HTML. They are meant to be
read rendered: on GitHub, or on the OpenTelemetry website, where OBI has a docs
section (`/docs/zero-code/obi/`) that is where these generated pages belong. The
published copies exist so the reference is fetchable at a stable URL alongside the
schema files.
