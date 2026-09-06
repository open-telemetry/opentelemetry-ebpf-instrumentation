# OBI Configuration v2.0 Design

Status: Draft for discussion  
Audience: OBI maintainers and contributors  
Scope: configuration model, schema, validation, and migration UX

The current configuration model has evolved organically with a focus on implementation needs and incremental user feedback.
This has led to structural inconsistencies, redundant controls, and a mix of user-facing and internal configuration in the same sections.
To address this, a user-centric redesign of the configuration schema is proposed here, optimizing for common user journeys, clear ownership of concerns, and a clean separation between user-facing configuration and internal implementation details.

Goals:

- Define a clear, consistent configuration schema that maps directly to user intent and common use cases.
- Provide an extension to the OpenTelemetry declarative configuration model that configures OBI-specific behavior.
- Guarantee a smooth migration path from the current v1 configuration shape to the new v2 shape, with clear validation and tooling support.
- Ensure the configuration can be used cleanly in both standalone daemon and Collector receiver deployments.

## Design principles

To ensure that the redesign is guided by consistent values and priorities, we define the following design principles for the configuration model, schema, validation, and migration UX.

- **Journey-first, user-mental-model first**
  - Configuration should match what users are trying to do, not internal implementation layering.
  - Structure should optimize for readability and safe default operation.

- **One concern, one place**
  - Every concern has one canonical home.
  - Avoid parallel knobs for the same behavior across sections.
  - OBI-specific concerns remain under `extensions.obi`, independent of generic instrumentation sections.

- **Compatible with OpenTelemetry declarative configuration**
  - Top-level OTel is authoritative for pipeline semantics:
    - Exporters/processors/samplers belong to top-level declarative OTel configuration sections.
    - OBI extension config should not reintroduce a competing pipeline model.
  - OBI-specific behavior lives under `extensions.obi`:
    - Runtime capture, selection, protocol controls, enrichment, and OBI limits are extension concerns.
    - OBI config should stay namespaced and composable.
  - Ownership boundary:
    - `instrumentation/development` is not merged into OBI-specific controls.
    - OBI behavior is configured through `extensions.obi` only.

- **Deployment-aware structure**
  - OBI runs in two modes: standalone daemon and Collector receiver.
  - Configuration structure should reflect which parts are valid in each mode.
  - The receiver-valid sub-config should have an unambiguous derivation from the standalone shape.
  - Standalone-only concerns (daemon process management, enrichment, log annotation) must not leak into receiver deployments.

- **Protocol-local ownership over global toggles**
  - Protocol behavior should be configured under each protocol section.
  - Enablement and filtering should be signal-scoped at the protocol/network ownership point.

- **Deterministic precedence over hidden heuristics**
  - Ordered rules should define precedence explicitly.
  - Configuration should avoid ambiguous override behavior.
  - Per-workload overrides use an explicit, closed vocabulary rather than generic deep-merge semantics.

- **Reduce redundancy and surprise**
  - Remove redundant gates that can silently disable already-configured behavior.
  - Keep implementation-only tuning internal unless it represents a stable user goal.
  - Keep naming concise when section context already conveys meaning.

- **Versioning should be explicit and layered**
  - The root declarative document version and OBI extension version are separate concerns.
  - Parsing flow should validate declarative shape first, then parse `extensions.obi` by its own version.

- **Backward compatibility is deliberate, not accidental**
  - Detect declarative vs legacy shape deterministically.
  - Legacy aliases are compatibility inputs that map into canonical v2 shape.

- **Proof-backed evolution**
  - Structural changes should be backed by explicit mapping, validation, and parity checks.
  - There exists a clear migration path to support users in moving from v1 to v2.

These principles are intentionally user-centered and decision-oriented, prioritizing clear user mental models, safe defaults, and a clean separation of concerns in the configuration schema.

## User Journeys

To ground this redesign in user needs, we start with the top user journeys and expectations.

### Onboard and activate

1. A user wants to instrument all services running on platform `<X>`.
    - Linux hosts (amd64/arm64)
    - Kubernetes workloads
    - Collector receiver deployments
2. A user wants to get useful default telemetry quickly, without deep OBI knowledge.
3. A user wants to enable network observability in addition to application observability.

### Target and scope

1. A user wants to instrument only `<Y>` services and exclude everything else.
    - process identity (executable path, PID)
    - network identity (open ports)
    - language identity (programming language)
    - Kubernetes/container identity (metadata, labels/annotations, containers-only)
2. A user wants to combine multiple target rules to scope instrumentation and control telemetry volume/cost.
3. A user wants to avoid instrumenting services that are already instrumented.
4. A user wants to apply per-service configuration (for example disable traces for one service, or set custom HTTP routes for another).

### Export and integrate

1. A user wants to send telemetry to an OTLP backend.
2. A user wants to expose Prometheus metrics when needed.
3. A user wants to leverage Collector processing and exporting pipelines when running OBI as a receiver.

### Enrich and optimize

1. A user wants to enable Kubernetes metadata enrichment for all instrumented services.
2. A user wants to enable protocol-specific parsing only for selected sources (for example HTTP payload extraction).
3. A user wants controls to limit cardinality and data growth.

### Operate in production

1. A user wants safe production operations with clear logging, profiling, and shutdown controls.
2. A user wants troubleshooting workflows for "no data", partial data, or unexpected cardinality spikes.
3. A user wants clear visibility into effective/resolved configuration before rollout.

### Validate and migrate

1. A user wants invalid or conflicting configuration to fail fast with actionable errors.
2. A user wants to migrate from legacy config keys to the new schema with minimal manual edits.
3. A user wants stable configuration patterns across environments with minimal duplication.

## Target v2.0 Configuration Shape

- [Runnable standalone example](./examples/default-configuration.yaml)
- [Default-values reference fragment](./examples/default-values-reference.fragment.yaml)
  (not a standalone configuration document)
- [JSON Schema](./obi-extension.schema.json) (schema for `extensions.obi`)

### High-level shape

At a high level, the target configuration shape is a standard [OpenTelemetry declarative configuration](https://github.com/open-telemetry/opentelemetry-configuration) document with a root `file_format` field and top-level sections for `resource`, `propagator`, `tracer_provider`, `meter_provider`, and `log_level`.
All OBI-specific configuration lives under `extensions.obi`.

The root `file_format` follows the declarative schema version (`major.minor`), not the upstream release tag. For the current stable declarative shape, the correct value is `file_format: "1.0"` rather than `1.0.0`, `1.0.0-rc.3`, or `1.0.0-rc.1`.
OBI validates this value and rejects unsupported declarative file-format versions.

### Stable declarative support scope

OBI adopts the standard declarative fields incrementally. For the first stable v2 configuration milestone, OBI supports:

| Declarative section | Stable v2 behavior |
| --- | --- |
| `file_format` | Required and restricted to `"1.0"`. |
| `resource` | Partial: string `host.name`, `host.id`, `service.name`, and `service.namespace` attributes are imported. Other attributes, detection configuration, and schema URLs are rejected by the target adapter in #2682. |
| `tracer_provider.sampler` | Partial: `always_on`, `always_off`, `trace_id_ratio_based`, and simple `parent_based` roots that use those samplers. |
| `tracer_provider.processors` | Partial: one batch processor with one OTLP exporter. Automatic migration emits gRPC; the gated standalone importer in [#2682](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/2682) also accepts HTTP/protobuf, HTTP/JSON, and declarative exporter headers. |
| `meter_provider.readers` | Partial: at most one periodic OTLP reader and one Prometheus development pull reader. Automatic migration emits OTLP/gRPC; the gated standalone importer in [#2682](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/2682) also accepts OTLP/HTTP and declarative exporter headers. |
| `log_level` | Supported for OBI daemon logging. OTel `trace*` and `debug*` severities map to `DEBUG`; `info*` to `INFO`; `warn*` to `WARN`; `error*` and `fatal*` to `ERROR`. `extensions.obi.daemon.logging.level` is not part of v2; use the top-level field. |
| `attribute_limits` | Rejected whenever present by the target adapter in #2682. |
| `disabled`, `distribution`, `propagator` | `disabled: true`, non-empty `distribution`, and non-empty propagator configuration are rejected. Empty/default placeholders do not enable runtime behavior. |
| `instrumentation/development`, `logger_provider` | Rejected when present by the target adapter in #2682. |

Environment-variable substitution depends on the loader. The upstream `otelconf/x.ParseYAML` path expands `${VAR}`, `${env:VAR}`, `${VAR:-fallback}`, and `${env:VAR:-fallback}` before decoding. OBI's internal `schema.ParseStandaloneYAML` parser decodes the supplied bytes directly, so callers using that parser must perform any desired substitution before calling it.

The `extensions.obi` block is divided by deployment scope:

- `capture`: valid in **all** deployment modes. Contains everything OBI needs to select workloads and capture telemetry. A receiver component places the children of this block beside its own `version`; it does not retain the `capture` wrapper.
- `enrich`, `correlation`, `daemon`: **standalone-mode only**. These sections are not valid in Collector receiver deployments. The Collector pipeline handles enrichment (via processors) and process lifecycle (logging, profiling, shutdown) in receiver mode.

The following is a non-runnable structural sketch. It omits exporter settings
and many values deliberately. Use the tested
[generated standalone fixture](examples/migration-v2.yaml) or
[receiver component body](examples/migration-receiver-v2.yaml) for validation.

```text
file_format: '1.0'
log_level: info

resource: {}
propagator: {}
tracer_provider: {}
meter_provider: {}

extensions:
  obi:
    version: "2.0"

    # Receiver-embeddable: valid in all deployment modes.
    capture:
      policy:
        default_action: include
        match_order: first_match_wins
      rules: []
      # ...
      instrumentation:
        http:
          enabled: { traces: true, metrics: true, body_size_metrics: false }
          filters: { traces: {}, metrics: {} }
        grpc:
          enabled: { traces: true, metrics: true }
          filters: { traces: {}, metrics: {} }
        sql:
          enabled: { traces: true, metrics: true }
          filters: { traces: {}, metrics: {} }
          mysql: {}
          postgres: {}
        redis:
          enabled: { traces: true, metrics: true }
          filters: { traces: {}, metrics: {} }
        kafka:
          enabled: { traces: true, metrics: true }
          filters: { traces: {}, metrics: {} }
        mongo:
          enabled: { traces: true, metrics: true }
          filters: { traces: {}, metrics: {} }
        couchbase:
          enabled: { traces: true, metrics: true }
          filters: { traces: {}, metrics: {} }
        dns:
          enabled: { traces: false, metrics: false }
          filters: { traces: {}, metrics: {} }
        gpu:
          enabled: { traces: true, metrics: true }
          filters: { traces: {}, metrics: {} }
      runtimes:
        go:
          enabled: true
          filter: {}
        nodejs:
          enabled: true
          filter: {}
        java:
          enabled: true
          filter: {}
          debug: {}
          attach_timeout: 10s
      network:
        capture: {}
      limits: {}
      engine: {}
      safety: {}
      channels: {}
      telemetry: {}

    # Standalone-mode only: not valid in Collector receiver deployments.
    enrich:
      enrichers:
        kubernetes: {}
      service_name: {}
      attributes: {}

    correlation:
      log_trace_annotation:
        enabled: false
        filter: {}
        field_names:
          trace_id: trace_id
          span_id: span_id
        plain_text:
          enabled: true
          placement: suffix
          multiline: first_line

    daemon:
      # ...
      logging: {}
      profiling: {}
      shutdown: {}
      internal_metrics: {}
      telemetry: {}
```

### `version` property

The `extensions.obi.version` field defines the version of the OBI extension schema being used.
It selects the supported extension schema; the only supported value is currently `"2.0"`.

### `capture` Section

The `extensions.obi.capture` section is the receiver-embeddable core of the OBI configuration.
It defines what OBI instruments and how it captures telemetry.
Its children are the **only** OBI extension fields valid in Collector receiver deployments.
Receiver configuration flattens those children beside its own `version` field rather than retaining the `capture` wrapper.

#### Why `capture` is a named grouping

Early design iterations kept all top-level OBI sections flat: `selection`, `instrumentation`, `runtimes`, `network`, `operations`, `enrich`, `correlation`.
The `capture` grouping was introduced for two reasons:

1. **Receiver embedding**: OBI runs in two deployment modes — standalone daemon and Collector receiver. In receiver mode, OBI is a telemetry source only. Side-effect features (k8s enrichment, log annotation) and process management (logging, profiling, shutdown) are not the receiver's responsibility — the Collector pipeline handles those. Having a single named block (`capture`) that represents exactly what the receiver shape flattens makes the boundary unambiguous and avoids requiring users or tools to manually enumerate which fields are valid.

2. **Correctness over documentation**: An alternative was a flat standalone structure with a `deployment: standalone | receiver` flag, where one parser would reject standalone-only fields in receiver mode. This was rejected because it makes the boundary a runtime enforcement concern rather than a structural schema concern. The named `capture` block communicates the boundary in standalone configuration, while the receiver uses its distinct flattened shape. Select the matching parser when validating: standalone is the default, and receiver configuration requires `--mode=receiver`.

`capture` contains:

- `policy`: global rule evaluation behavior (default action, match order, timing).
- `rules`: ordered workload selection rules (include/exclude by process identity, Kubernetes metadata, etc.).
- `instrumentation`: protocol-specific capture controls (HTTP, gRPC, SQL, Redis, Kafka, MongoDB, Couchbase, DNS, GPU, Aerospike).
- `runtimes`: language runtime injection controls (Go probes, Node.js SIGUSR1, Java agent attachment).
- `network`: network flow capture configuration.
- `limits`: cardinality and memory guardrails.
- `engine`: eBPF engine internals (batching, pid filter, BPF filesystem, propagation, traffic backend, transaction limits, debug).
- `safety`: system capability enforcement checks.
- `channels`: internal backpressure controls.
- `telemetry`: reporter cache sizes and metric TTL tuning for OBI capture internals.

#### Workload selection: `capture.policy` and `capture.rules`

`capture.policy` defines global rule evaluation behavior, and `capture.rules` is an ordered list of workload inclusion/exclusion rules.
Rules are based on process identity, network identity, language, Kubernetes metadata, and already-instrumented status.
These are the primary user controls for defining which services get instrumented by OBI.

The target adapter in
[#2682](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/2682)
accepts `first_match_wins` and `last_match_wins`. Runtime selection always
gives matching exclusions precedence. To preserve that behavior,
`first_match_wins` requires exclusions before includes, while
`last_match_wins` requires includes before exclusions. With
`first_match_wins`, the first matching YAML include refinement wins. The
migrator reverses effective v1 include-selector order because the v1 runtime
applies the later matching selector's refinement. Preserve generated rule
order during migration. When multiple include rules use an export or HTTP-route
refinement, omitting that refinement on another include rule resets it instead
of inheriting a prior rule's value. The migrator therefore rejects v1 selector
lists that mix explicit and omitted `exports`, or mix explicit and omitted
`routes`; make each field explicit on every selector and test overlapping and
selector-only matches, or keep v1 when behavior depends on conditional
inheritance. Writing `rules: []` explicitly also removes the generated
built-in workload exclusions.

**Why `policy` and `rules` are direct children of `capture`, not nested under `capture.selection`**

An earlier draft had a `selection` sub-section under `capture` (i.e., `capture.selection.policy` and `capture.selection.rules`).
The extra nesting was removed for the following reasons:

- `capture.rules` is the field the vast majority of users write. Any indirection before reaching it is friction on the most common path.
- The `selection` grouping added no semantic clarity — within `capture`, everything is selection-and-capture configuration. The word `selection` was a label for a concept that `capture` already names.
- Removing the indirection saves one nesting level on every rule users write, with no loss of meaning.
- `capture.policy` and `capture.rules` read naturally as "the capture policy" and "the capture rules", reinforcing the parent section's meaning rather than fighting it.

#### Effective discovery selector export shape

The v1-to-v2 export path writes effective discovery selectors into `capture.rules`.
It does not only copy `discovery.instrument` literally. It uses the same effective selector inputs as runtime discovery:

- `target_pids` becomes a single include rule that matches `process.target_pids`.
- Modern glob selectors from `discovery.instrument`, `discovery.exclude_instrument`, and environment auto-target fields become include/exclude rules with `*_glob` match fields.
- Legacy regex selectors from `discovery.services`, `discovery.exclude_services`, and `executable_path` become include/exclude rules with `*_regex` match fields. The `open_port` fallback becomes `open_ports`.
- Default workload excludes and already-instrumented-service detection become explicit exclude rules.

`discovery.excluded_linux_system_paths` is not a workload exclusion. It skips
an early language-detection pass while an explicitly selected process still
reaches later type detection. Its built-in default remains internal runtime
behavior; custom values have no v2 field and migration rejects them.

Known `match.process` fields exported today:

| v2 field | Value shape | Source |
|---|---|---|
| `open_ports` | String int/range list, for example `"8080,9090-9091"` | v1 `open_ports` / `open_port` |
| `target_pids` | Integer array | v1 `target_pids` |
| `language_glob` | String array | v1 glob `languages` |
| `language_regex` | String regex | legacy v1 regex `languages` |
| `cmd_args_glob` | String array | v1 glob `cmd_args` |
| `cmd_args_regex` | String regex | legacy v1 regex `cmd_args` |
| `exe_path_glob` | String array | v1 glob `exe_path` |
| `exe_path_regex` | String regex | legacy v1 regex `exe_path` / `exe_path_regexp` and `executable_path` |
| `containers_only` | Boolean | v1 `containers_only` |
| `exports_otlp` | Object with `port` and `protocol` | v1 `exclude_otel_instrumented_services` |

Known `match.kubernetes` fields exported today:

| v2 field | Value shape | Source |
|---|---|---|
| `namespace_glob` | String array | v1 `k8s_namespace` in glob selectors |
| `namespace_regex` | String regex | legacy v1 `k8s_namespace` in regex selectors |
| `metadata_glob` | Map of Kubernetes metadata key to string array | Non-namespace v1 Kubernetes metadata in glob selectors |
| `metadata_regex` | Map of Kubernetes metadata key to regex string | Non-namespace v1 Kubernetes metadata in legacy regex selectors |
| `pod_labels` | Map of pod label key to string array | v1 `k8s_pod_labels` in glob selectors |
| `pod_labels_regex` | Map of pod label key to regex string | legacy v1 `k8s_pod_labels` in regex selectors |
| `pod_annotations` | Map of pod annotation key to string array | v1 `k8s_pod_annotations` in glob selectors |
| `pod_annotations_regex` | Map of pod annotation key to regex string | legacy v1 `k8s_pod_annotations` in regex selectors |

`metadata_glob` and `metadata_regex` intentionally exclude `k8s_namespace`; namespace has first-class fields because it is the most common Kubernetes selector.
Other allowed metadata keys currently include `k8s_pod_name`, `k8s_deployment_name`, `k8s_replicaset_name`, `k8s_daemonset_name`, `k8s_statefulset_name`, `k8s_job_name`, `k8s_cronjob_name`, `k8s_owner_name`, `k8s_container_name`, and `container_name`.

#### Language-detection path skips are not capture rules

The v1 `discovery.excluded_linux_system_paths` field limits the cost of
preliminary language detection for executables under common Linux system
paths. It does not express workload-selection intent. A process under one of
these paths cannot match a language selector because its preliminary language
detection is skipped, but it can still be selected by executable path, open
port, PID, or metadata. Once selected, OBI detects its executable type for the
instrumentation pipeline.

Config v2 does not expose this implementation-tuning field and does not
translate its paths into `capture.rules`. The built-in path list remains an
internal runtime default for both standalone and receiver deployments.
Translating it into exclude rules would widen a language-detection optimization
into a hard capture exclusion and could suppress explicitly selected services.

Migration accepts the v1 default value, including when it is written
explicitly, because the effective behavior is preserved. A custom or empty v1
value cannot be represented in v2 and causes migration to fail with the exact
source field. Operators who intend to exclude workloads from capture should
write explicit `capture.rules` instead.

#### Per-workload refinement: `refine` on include rules

Include rules may carry an optional `refine` block that overrides global defaults for matched workloads.

**Why `refine` exists**

v1 supported per-selection-rule overrides for exports, sampler, routes, and metrics (`ExportModes`, `SamplerConfig`, `Routes`, `SvcMetricsConfig`).
The initial v2 design had no equivalent, which would have required users to either apply global settings to all workloads uniformly or replace the whole config per environment.
This was raised as a key gap by reviewers (grcevski, fstab) — a concrete example: globally emit metrics only, but for a specific namespace emit traces as well; or globally use heuristic routes, but for a specific service specify exact path patterns.

**Why `refine` uses an explicit closed vocabulary, not generic deep-merge**

The alternative to an explicit vocabulary is a `refine` block that accepts any subset of the global config shape and deep-merges it.
This was rejected because:

- Deep-merge semantics are ambiguous for arrays (append vs. replace?), maps (key-level merge vs. whole-map replace?), and absent fields (inherit vs. zero?). Each ambiguity needs a specified rule, and each rule is a source of user confusion.
- The actual v1 per-rule overrides were a small, well-defined set. Generalizing to an arbitrary deep-merge would have supported hypothetical cases at the cost of making the common cases harder to reason about.
- An explicit vocabulary makes the schema self-documenting: users see exactly what can be overridden per workload.

Current overridable fields in `refine`:

- `exports`: override which signals (`traces`, `metrics`) are emitted for this workload.
- `http.routes`: refine the direction-scoped HTTP route policy for this workload.

The schema reserves refinement `http.filters`, but the target runtime adapter
rejects a non-empty value. Do not use it to narrow a migrated configuration;
filter semantics remain tracked in
[#1282](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1282).

New fields can be added to the `refine` vocabulary deliberately as use cases emerge.

Example use cases:

```yaml
capture:
  rules:
    # Disable traces for a low-priority namespace; keep metrics.
    - action: include
      name: low-priority-ns
      match:
        kubernetes:
          namespace_glob: ["staging-*"]
      refine:
        exports:
          traces: false
          metrics: true

    # Custom HTTP routes for a service that uses path parameters.
    - action: include
      name: orders-service
      match:
        kubernetes:
          namespace_glob: ["orders"]
      refine:
        http:
          routes:
            incoming:
              patterns:
                - /orders/{id}
                - /orders/{id}/items
              ignored_patterns:
                - /health
              unmatched: path
            outgoing:
              patterns:
                - /inventory/{id}
              unmatched: wildcard
```

`incoming` applies to HTTP requests handled by the matched workload, equivalent to v1 `routes.incoming`.
`outgoing` applies to HTTP requests made by the matched workload, equivalent to v1 `routes.outgoing`.
Both directions accept the same fields: `patterns`, `ignored_patterns`, `ignore_mode`, `unmatched`, `wildcard_char`, and `max_path_segment_cardinality`.
For a matched workload, an omitted direction or field inherits the corresponding global value.
An explicitly configured scalar replaces the global scalar, and an explicitly configured array replaces the global array; use an empty array to clear inherited patterns.

Sampling overrides are **not** part of the `refine` block.
See the [Sampling model](#sampling-model) section below.

### Sampling model

Sampling is owned by top-level OTel declarative configuration under
`tracer_provider.sampler`. The current runtime adapter supports the built-in
always-on, always-off, trace-ID-ratio, and corresponding parent-based shapes.
For example, this provider fragment uses parent-based ratio sampling:

```yaml
tracer_provider:
  sampler:
    parent_based:
      root:
        trace_id_ratio_based:
          ratio: 0.10
```

Per-workload v1 samplers have no current v2 migration target. Vendor sampler
shapes such as `obi_rule_based` are not imported by the runtime. Keep v1 when
workload-specific sampling is required; broader per-workload pipeline work is
tracked in
[#923](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/923).

### `capture.instrumentation` Section

The `capture.instrumentation` section defines protocol-specific instrumentation controls, including enablement and filtering for traces and metrics.

All protocols (HTTP, gRPC, SQL, Redis, Kafka, MongoDB, Couchbase, DNS, GPU,
Aerospike) have a consistent base structure for trace and metric enablement.
Each protocol can also have specific subsections; for example, SQL has `mysql`
and `postgres`, while HTTP has `routes.discovery`.

Filter fields are schema-modelled but only a compatibility subset is imported.
The target adapter compares every application protocol's trace and metric maps
with `http.filters.traces` and rejects any difference because the runtime uses
one application filter. It likewise requires identical trace and metric maps
within network flow capture and within TCP stats. Migrated v1 filters remain
fanned out and equal pending
[#1282](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1282).

HTTP route normalization is directional. `http.routes.incoming` applies to requests handled by an instrumented workload and `http.routes.outgoing` applies to requests made by it.
Each direction has the same route-policy fields: `patterns`, `ignored_patterns`, `ignore_mode`, `unmatched`, `wildcard_char`, and `max_path_segment_cardinality`.
`wildcard_char` may be empty or contain one nonzero ASCII character so the value remains compatible with the byte-based route classifier.
Global route discovery remains under `http.routes.discovery` because harvesting is configured for the capture engine rather than for an individual traffic direction.

HTTP `payload_extraction` uses the same list-based enablement model as other instrumentation selectors:

- `payload_extraction.enabled` is the only enablement surface.
- Concrete values currently supported are `graphql`, `elasticsearch`, `aws`, `sqlpp`, `openai`, `anthropic`, `gemini`, `qwen`, `bedrock`, `mcp`, `embedding`, `rerank`, `retrieval`, `ollama`, `openai_compatible`, `jsonrpc`, and `enrichment`.
- Nested extractor blocks are for tuning, not duplicate enablement. For example, `payload_extraction.sqlpp.endpoint_patterns` refines SQL++ matching after `sqlpp` is enabled in the list.
- If future aliases or families are needed, they should be added as values in the same `enabled` list rather than introducing parallel knobs.

### `capture.runtimes` Section

The `capture.runtimes` section defines how language-specific runtime instrumentation injection mechanisms are controlled.
These include Go probes, Node.js SIGUSR1 signal injection, and Java agent attachment.

Unlike protocol instrumentation, runtimes are not about capturing specific telemetry signals — they are about *how* to instrument a service once it's selected.
Each runtime has a simple structure: `enabled` (boolean) controls whether to attempt injection.
Java also includes additional runtime-specific configuration such as debug controls and attachment timeout.
Runtime `filter` fields are reserved by the schema but non-empty values are not
supported by the current adapter; use capture rules for workload selection.

### `capture.network` Section

The `capture.network` section defines how network observability is configured, including endpoint identity, selection criteria, flow lifecycle controls, interface discovery behavior, enrichment options, and diagnostics.
This section is the primary user control for defining how OBI captures and processes network telemetry.

The current shape separates packet/flow capture from TCP stats capture:

- `capture.network.capture` controls network flow capture and flow-derived telemetry.
- `capture.network.stats` controls TCP stats telemetry. `enabled` is the stats master switch, and `features` lists enabled stats families: `tcp_rtt`, `tcp_failed_connections`, `tcp_retransmits`, and `tcp_io`.

`tcp_io` can produce substantially more events than the other stats families, so users should opt into it deliberately when they need per-send/per-receive I/O stats.

### `capture.engine` Section

The `capture.engine` section controls eBPF engine internals: event batching, PID-based filtering, BPF filesystem path, context propagation mode, traffic control backend, transaction duration limits, and debug toggles.

**Why `engine`, not `capture.capture`**

Earlier drafts named this sub-section `capture` (i.e., `operations.capture`), which would have produced the awkward path `capture.capture.*` after the restructure.
It was renamed `engine` to accurately describe what it contains (eBPF engine internals) while remaining deployment-neutral — advanced users who tune these settings already know they are configuring BPF behavior.
The alternative `ebpf` was considered but rejected as more implementation-specific than `engine`.

### `enrich` Section

The `extensions.obi.enrich` section defines enrichment behavior for telemetry, including Kubernetes metadata, service naming policy, and general attribute enrichment rules.
This section is **standalone-mode only**.

#### Why `enrich` is standalone-only

In Collector receiver deployments, OBI is a telemetry source. Enrichment is the Collector's responsibility:

- The [`k8sattributesprocessor`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/k8sattributesprocessor) covers Kubernetes pod/namespace/deployment metadata and service name derivation following OTel semantic conventions.
- Running OBI's built-in k8s enricher alongside `k8sattributesprocessor` in the same pipeline results in duplicate Kubernetes API queries and potentially conflicting attribute values.
- Attribute enrichment and service naming rules in `enrich` are conceptually a post-capture processing step, which belongs in the Collector pipeline in receiver mode.

This was raised directly by reviewers (dmitryax) who noted the overlap with existing Collector processors.

In standalone mode, `enrich` remains essential — there is no Collector pipeline to delegate enrichment to.

For Kubernetes environments using OBI as a receiver, omit `enrich` entirely
and use `k8sattributesprocessor` in the Collector pipeline. Receiver validation
rejects the standalone-only `enrich` section.

The `mode` field supports: `autodetect` (default — enable if k8s environment is detected), `enabled`, and `disabled`.

### `correlation` Section

The `extensions.obi.correlation` section defines trace-context correlation features that propagate OBI-generated trace context into external streams.
Unlike telemetry instrumentation (protocol signals), correlation features operate *after* traces are captured to enrich related observability data.

For example, `log_trace_annotation` allows trace context to be injected into application logs from selected services, linking logs to traces through context correlation.

JSON object logs receive structured fields. Plain-text logs receive space-separated `key=value` fields by default. `field_names` configures the literal keys for both representations. `plain_text.enabled` disables only plain-text annotation, while `placement` selects `prefix` or `suffix` and `multiline` selects `first_line`, `last_line`, or `each_line` within each intercepted write.

This section is **standalone-mode only**.

#### Why `correlation` is standalone-only, and the future of log trace annotation

`log_trace_annotation` is a side-effectful operation — it writes back to log streams, which is not a telemetry-source concern.
When running as a Collector receiver, these side effects are not appropriate for a receiver component.
Log trace annotation as a standalone Collector component (e.g., a processor or connector) is planned as a separate deliverable, separate from the OBI receiver configuration.

### `daemon` Section

The `extensions.obi.daemon` section defines OBI daemon process controls.
This section is **standalone-mode only** — in Collector receiver deployments, the Collector manages all of these concerns.

**Why `daemon`, not `operations`**

The previous design had a flat `operations` section containing a mix of capture-valid fields (batching, BPF filesystem, limits) and daemon-only fields (logging, profiling, shutdown, internal metrics).
The restructure into `capture` and `daemon` emerged from analyzing which fields are valid in receiver mode:

- Fields that govern eBPF capture behavior are valid in all modes → moved into `capture.*`
- Fields that govern the OBI process itself are not valid in receiver mode → grouped in `daemon`

The name `daemon` was chosen over `process` (too generic), `agent` (overloaded in OTel), `operations` (too broad after the split), and `self` (too terse for a configuration section name).
`daemon` is honest and unambiguous: it configures the OBI daemon process.

`daemon` contains:

- `logging`: OBI process log format, startup configuration output format, and debug trace output mode. Use top-level `log_level` for OBI process log verbosity.
- `profiling`: optional pprof endpoint for the OBI process.
- `shutdown`: graceful shutdown timeout.
- `internal_metrics`: OBI daemon's own metrics export (Prometheus or OTLP).
- `telemetry.metrics.prometheus`: Prometheus-exporter-specific metric shaping for OBI standalone output.

### Compatibility and mapping from v1

v2 is a structural redesign of v1, with deterministic compatibility mapping.
The table lists fields whose canonical location or behavior changes, including
explicit no-target rows for removed settings.
The migration command combines round-trip comparison with guards for
non-1:1 mappings and rejects detected values that cannot be preserved. See the
[migration guide](migration.md#handle-fields-that-need-manual-intervention)
for unsupported and manual cases.

Important mapping notes:

- OTel pipeline structure ownership moved to top-level declarative sections:
  - the automatically migrated `otel_metrics_export` OTLP/gRPC subset → `meter_provider.*`; gated OTLP/HTTP uses the manual provider mapping in the migration guide
  - `prometheus_export.port` → `meter_provider.*`
  - the automatically migrated `otel_traces_export` OTLP/gRPC and global sampler subset → `tracer_provider.*`; gated OTLP/HTTP uses the manual provider mapping in the migration guide
- The old flat `operations` section is split by deployment scope:
  - Capture-valid fields move into `extensions.obi.capture.*` (valid in all deployment modes).
  - Daemon-only fields move into `extensions.obi.daemon.*` (standalone mode only).
- Some mappings are non-1:1:
  - `filter.application` fans out to `capture.instrumentation.<protocol>.filters.{traces,metrics}`.
  - `filter.network` fans out to `capture.network.capture.filters.{traces,metrics}`.
  - `filter.stats` fans out to `capture.network.stats.filters.{traces,metrics}`.
  - Supported `metrics.features` values map to `capture.instrumentation.<protocol>.enabled.metrics`, `capture.network.capture.enabled`, and `capture.network.stats.{enabled,features}`. These are application RED, basic network flow, and individual network-stat features.
  - Discovery selectors are exported as effective `capture.rules` after legacy/new selector precedence is resolved.
  - `discovery.skip_go_specific_tracers` maps to `capture.runtimes.go.enabled` with inverted semantics.

| v1 field | v2 canonical location | Notes |
|---|---|---|
| `attributes.extra_group_attributes` | `extensions.obi.enrich.attributes.extra_group_attributes` | Move |
| `attributes.host_id.override` | String `resource.attributes[]` entry named `host.id` | Move to standard resource metadata |
| `attributes.instance_id.override_hostname` | String `resource.attributes[]` entry named `host.name` | Move to standard resource metadata |
| `attributes.kubernetes.cluster_name` | `extensions.obi.enrich.enrichers.kubernetes.cluster_name` | Move |
| `attributes.kubernetes.disable_informers` | `extensions.obi.enrich.enrichers.kubernetes.informers.disabled` | Move + rename |
| `attributes.kubernetes.drop_external` | `extensions.obi.enrich.enrichers.kubernetes.drop_external` | Move |
| `attributes.kubernetes.enable` | `extensions.obi.enrich.enrichers.kubernetes.mode` | Reshape `true`, `false`, and `autodetect` to `enabled`, `disabled`, and `autodetect` |
| `attributes.kubernetes.informers_sync_timeout` | `extensions.obi.enrich.enrichers.kubernetes.informers.initial_sync_timeout` | Move |
| `attributes.kubernetes.informers_resync_period` | `extensions.obi.enrich.enrichers.kubernetes.informers.resync_period` | Move |
| `attributes.kubernetes.kubeconfig_path` | `extensions.obi.enrich.enrichers.kubernetes.auth.kubeconfig_path` | Move |
| `attributes.kubernetes.meta_cache_address` | `extensions.obi.enrich.enrichers.kubernetes.metadata_cache.address` | Move + rename |
| `attributes.kubernetes.meta_restrict_local_node` | `extensions.obi.enrich.enrichers.kubernetes.metadata_cache.restrict_local_node` | Move + rename |
| `attributes.kubernetes.meta_source_labels.service_name` | `extensions.obi.enrich.enrichers.kubernetes.metadata_cache.source_labels.service_name` | Move |
| `attributes.kubernetes.meta_source_labels.service_namespace` | `extensions.obi.enrich.enrichers.kubernetes.metadata_cache.source_labels.service_namespace` | Move |
| `attributes.kubernetes.reconnect_initial_interval` | `extensions.obi.enrich.enrichers.kubernetes.informers.reconnect_initial_interval` | Move |
| `attributes.kubernetes.resource_labels` | `extensions.obi.enrich.enrichers.kubernetes.resource_labels` | Move |
| `attributes.kubernetes.service_name_template` | `extensions.obi.enrich.enrichers.kubernetes.service_name_template` | Move |
| `attributes.metadata_retry.max_interval` | `extensions.obi.enrich.attributes.metadata_retry.max_interval` | Move |
| `attributes.metadata_retry.start_interval` | `extensions.obi.enrich.attributes.metadata_retry.start_interval` | Move |
| `attributes.metadata_retry.timeout` | `extensions.obi.enrich.attributes.metadata_retry.timeout` | Move |
| `attributes.metric_span_names_limit` | `extensions.obi.capture.limits.metric_span_names` | Move + rename |
| `attributes.rename_unresolved_hosts` | `extensions.obi.enrich.service_name.unresolved_hosts.names.default` | Move |
| `attributes.rename_unresolved_hosts_incoming` | `extensions.obi.enrich.service_name.unresolved_hosts.names.incoming` | Move |
| `attributes.rename_unresolved_hosts_outgoing` | `extensions.obi.enrich.service_name.unresolved_hosts.names.outgoing` | Move |
| `attributes.select` | `extensions.obi.enrich.attributes.select` | Move |
| `channel_buffer_len` | `extensions.obi.capture.channels.buffer_len` | Move |
| `channel_send_timeout` | `extensions.obi.capture.channels.send_timeout` | Move |
| `channel_send_timeout_panic` | `extensions.obi.capture.channels.panic_on_send_timeout` | Move + rename |
| `discovery.bpf_pid_filter_off` | `extensions.obi.capture.engine.pid_filter.disabled` | Move + rename |
| `discovery.default_otlp_grpc_port` | `extensions.obi.capture.rules[].match.process.exports_otlp.port` | Emitted only when `exclude_otel_instrumented_services` is enabled |
| `discovery.default_exclude_instrument` | `extensions.obi.capture.rules[]` (exclude rules with glob selectors) | Move + reshape |
| `discovery.default_exclude_services` | `extensions.obi.capture.rules[]` (exclude rules with legacy regex selectors) | Legacy move + reshape |
| `discovery.disabled_route_harvesters` | `extensions.obi.capture.instrumentation.http.routes.discovery.disabled_languages` | Move + rename |
| `discovery.exclude_instrument` | `extensions.obi.capture.rules[]` (exclude rules with glob selectors) | Move + reshape |
| `discovery.exclude_otel_instrumented_services` | `extensions.obi.capture.rules[].match.process.exports_otlp` (exclude rule) | Move + reshape |
| `discovery.exclude_services` | `extensions.obi.capture.rules[]` (exclude rules with legacy regex selectors) | Legacy move + reshape |
| `discovery.excluded_linux_system_paths` | *No v2 field* | The built-in default remains an internal language-detection optimization. Migration rejects custom or explicitly empty values; an exclude rule is not equivalent. |
| `discovery.instrument` | `extensions.obi.capture.rules[]` (include rules with glob selectors) | Effective match fields only; see selector limitations in the migration guide |
| `discovery.instrument[].exports` | `extensions.obi.capture.rules[].refine.exports.{traces,metrics}` | Logs cannot be represented |
| `discovery.instrument[].routes.incoming` | `extensions.obi.capture.rules[].refine.http.routes.incoming.patterns` | Supported only when global `routes.patterns` is empty |
| `discovery.instrument[].routes.outgoing` | `extensions.obi.capture.rules[].refine.http.routes.outgoing.patterns` | Supported only when global `routes.patterns` is empty |
| `discovery.min_process_age` | `extensions.obi.capture.policy.min_process_age` | Move |
| `discovery.poll_interval` | `extensions.obi.capture.policy.poll_interval` | Move |
| `discovery.route_harvester_advanced.java_harvest_delay` | `extensions.obi.capture.instrumentation.http.routes.discovery.java.delay` | Move + rename |
| `discovery.route_harvester_timeout` | `extensions.obi.capture.instrumentation.http.routes.discovery.timeout` | Move + rename |
| `discovery.services` | `extensions.obi.capture.rules[]` (include rules with legacy regex selectors) | Effective match fields only; see selector limitations in the migration guide |
| `discovery.services[].exports` | `extensions.obi.capture.rules[].refine.exports.{traces,metrics}` | Logs cannot be represented |
| `discovery.services[].routes.incoming` | `extensions.obi.capture.rules[].refine.http.routes.incoming.patterns` | Supported only when global `routes.patterns` is empty |
| `discovery.services[].routes.outgoing` | `extensions.obi.capture.rules[].refine.http.routes.outgoing.patterns` | Supported only when global `routes.patterns` is empty |
| `discovery.skip_go_specific_tracers` | `extensions.obi.capture.runtimes.go.enabled` | Inverted boolean mapping |
| `ebpf.batch_length` | `extensions.obi.capture.engine.batching.batch_length` | Move |
| `ebpf.batch_timeout` | `extensions.obi.capture.engine.batching.batch_timeout` | Move |
| `ebpf.bpf_debug` | `extensions.obi.capture.engine.debug.bpf` | Move |
| `ebpf.bpf_fs_path` | `extensions.obi.capture.engine.bpf_filesystem.path` | Move + rename |
| `ebpf.buffer_sizes.tcp` | `extensions.obi.capture.network.capture.buffer_size` | Move |
| `ebpf.buffer_sizes.http` | `extensions.obi.capture.instrumentation.http.buffer_size` | Move |
| `ebpf.buffer_sizes.kafka` | `extensions.obi.capture.instrumentation.kafka.buffer_size` | Move |
| `ebpf.buffer_sizes.mssql` | `extensions.obi.capture.instrumentation.sql.mssql.buffer_size` | Move |
| `ebpf.buffer_sizes.mysql` | `extensions.obi.capture.instrumentation.sql.mysql.buffer_size` | Move |
| `ebpf.buffer_sizes.postgres` | `extensions.obi.capture.instrumentation.sql.postgres.buffer_size` | Move |
| `ebpf.context_propagation` | `extensions.obi.capture.engine.propagation.context_propagation` | Move |
| `ebpf.couchbase_db_cache_size` | `extensions.obi.capture.instrumentation.couchbase.db_cache_size` | Move |
| `ebpf.disable_black_box_cp` | `extensions.obi.capture.engine.propagation.disable_black_box_cp` | Move |
| `ebpf.dns_request_timeout` | `extensions.obi.capture.instrumentation.dns.request_timeout` | Move |
| `ebpf.force_bpf_map_reader` | `extensions.obi.capture.engine.traffic.force_map_reader` | Move + rename |
| `ebpf.go_http_client_buffer_timeout` | `extensions.obi.capture.instrumentation.http.go_http_client_buffer_timeout` | Move |
| `ebpf.high_request_volume` | `extensions.obi.capture.engine.traffic.high_request_volume` | Move |
| `ebpf.heuristic_sql_detect` | `extensions.obi.capture.instrumentation.sql.heuristic_detect` | Move + rename |
| `ebpf.http_request_timeout` | `extensions.obi.capture.instrumentation.http.request_timeout` | Move |
| `ebpf.instrument_cuda` | `extensions.obi.capture.instrumentation.gpu.enabled_mode` | Move + reshape |
| `ebpf.kafka_topic_uuid_cache_size` | `extensions.obi.capture.instrumentation.kafka.topic_uuid_cache_size` | Move |
| `ebpf.log_enricher.cache_size` | `extensions.obi.correlation.log_trace_annotation.cache.size` | Move + rename |
| `ebpf.log_enricher.cache_ttl` | `extensions.obi.correlation.log_trace_annotation.cache.ttl` | Move + rename |
| `ebpf.log_enricher.async_writer_workers` | `extensions.obi.correlation.log_trace_annotation.async_writer.workers` | Move + rename |
| `ebpf.log_enricher.async_writer_channel_len` | `extensions.obi.correlation.log_trace_annotation.async_writer.channel_len` | Move + rename |
| `ebpf.log_enricher.field_names.trace_id` | `extensions.obi.correlation.log_trace_annotation.field_names.trace_id` | Move |
| `ebpf.log_enricher.field_names.span_id` | `extensions.obi.correlation.log_trace_annotation.field_names.span_id` | Move |
| `ebpf.log_enricher.plain_text.enabled` | `extensions.obi.correlation.log_trace_annotation.plain_text.enabled` | Move |
| `ebpf.log_enricher.plain_text.placement` | `extensions.obi.correlation.log_trace_annotation.plain_text.placement` | Move |
| `ebpf.log_enricher.plain_text.multiline` | `extensions.obi.correlation.log_trace_annotation.plain_text.multiline` | Move |
| `ebpf.maps_config.global_scale_factor` | `extensions.obi.capture.engine.maps.global_scale_factor` | Move + rename |
| `ebpf.max_transaction_time` | `extensions.obi.capture.engine.transactions.max_duration` | Move + rename |
| `ebpf.mongo_requests_cache_size` | `extensions.obi.capture.instrumentation.mongo.requests_cache_size` | Move |
| `ebpf.mssql_prepared_statements_cache_size` | `extensions.obi.capture.instrumentation.sql.mssql.prepared_statements_cache_size` | Move |
| `ebpf.mysql_prepared_statements_cache_size` | `extensions.obi.capture.instrumentation.sql.mysql.prepared_statements_cache_size` | Move |
| `ebpf.payload_extraction.http.graphql.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `graphql` | Move + normalize |
| `ebpf.payload_extraction.http.elasticsearch.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `elasticsearch` | Move + normalize |
| `ebpf.payload_extraction.http.aws.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `aws` | Move + normalize |
| `ebpf.payload_extraction.http.sqlpp.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `sqlpp` | Move + normalize |
| `ebpf.payload_extraction.http.sqlpp.endpoint_patterns` | `extensions.obi.capture.instrumentation.http.payload_extraction.sqlpp.endpoint_patterns` | Move |
| `ebpf.payload_extraction.http.genai.openai.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `openai` | Move + normalize |
| `ebpf.payload_extraction.http.genai.anthropic.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `anthropic` | Move + normalize |
| `ebpf.payload_extraction.http.genai.gemini.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `gemini` | Move + normalize |
| `ebpf.payload_extraction.http.genai.qwen.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `qwen` | Move + normalize |
| `ebpf.payload_extraction.http.genai.bedrock.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `bedrock` | Move + normalize |
| `ebpf.payload_extraction.http.genai.mcp.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `mcp` | Move + normalize |
| `ebpf.payload_extraction.http.genai.ollama.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `ollama` | Move + normalize |
| `ebpf.payload_extraction.http.genai.openai_compatible.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `openai_compatible` | Move + normalize |
| `ebpf.payload_extraction.http.genai.openai_compatible.gateways` | `extensions.obi.capture.instrumentation.http.payload_extraction.openai_compatible.gateways` | Move |
| `ebpf.payload_extraction.http.genai.embedding.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `embedding` | Move + normalize |
| `ebpf.payload_extraction.http.genai.rerank.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `rerank` | Move + normalize |
| `ebpf.payload_extraction.http.genai.retrieval.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `retrieval` | Move + normalize |
| `ebpf.payload_extraction.http.jsonrpc.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `jsonrpc` | Move + normalize |
| `ebpf.payload_extraction.http.enrichment.enabled` | `extensions.obi.capture.instrumentation.http.payload_extraction.enabled[]` contains `enrichment` | Move + normalize |
| `ebpf.payload_extraction.http.enrichment.policy.default_action.headers` | `extensions.obi.capture.instrumentation.http.payload_extraction.enrichment.policy.default_action.headers` | Move |
| `ebpf.payload_extraction.http.enrichment.policy.default_action.body` | `extensions.obi.capture.instrumentation.http.payload_extraction.enrichment.policy.default_action.body` | Move |
| `ebpf.payload_extraction.http.enrichment.policy.obfuscation_string` | `extensions.obi.capture.instrumentation.http.payload_extraction.enrichment.policy.obfuscation_string` | Move |
| `ebpf.payload_extraction.http.enrichment.rules` | `extensions.obi.capture.instrumentation.http.payload_extraction.enrichment.rules` | Move |
| `ebpf.postgres_prepared_statements_cache_size` | `extensions.obi.capture.instrumentation.sql.postgres.prepared_statements_cache_size` | Move |
| `ebpf.protocol_debug_print` | `extensions.obi.capture.engine.debug.protocol_print` | Move |
| `ebpf.redis_db_cache.enabled` | `extensions.obi.capture.instrumentation.redis.db_cache.enabled` | Move |
| `ebpf.redis_db_cache.max_size` | `extensions.obi.capture.instrumentation.redis.db_cache.max_size` | Move |
| `ebpf.track_request_headers` | `extensions.obi.capture.instrumentation.http.track_request_headers` | Move |
| `ebpf.traffic_control_backend` | `extensions.obi.capture.engine.traffic.control_backend` | Move + rename |
| `ebpf.override_bpfloop_enabled` | `extensions.obi.capture.engine.propagation.override_bpfloop_enabled` | Move |
| `ebpf.wakeup_len` | `extensions.obi.capture.engine.batching.wakeup_len` | Move |
| `enforce_sys_caps` | `extensions.obi.capture.safety.enforce_system_capabilities` | Move + rename |
| `executable_path` | `extensions.obi.capture.rules[].match.process.exe_path_regex` (include rule) | Legacy fallback selector |
| `open_port` | `extensions.obi.capture.rules[].match.process.open_ports` (include rule) | Fallback selector |
| `target_pids` | `extensions.obi.capture.rules[].match.process.target_pids` (include rule) | Fallback selector |
| `filter.application` | `extensions.obi.capture.instrumentation.<protocol>.filters.{traces,metrics}` | Fan-out to all protocols/signals |
| `filter.network` | `extensions.obi.capture.network.capture.filters.{traces,metrics}` | Fan-out to both signals |
| `filter.stats` | `extensions.obi.capture.network.stats.filters.{traces,metrics}` | Fan-out to both signals |
| `internal_metrics.bpf_metric_scrape_interval` | `extensions.obi.daemon.internal_metrics.bpf.scrape_interval` | Move + rename |
| `internal_metrics.exporter` | `extensions.obi.daemon.internal_metrics.exporter` | Move |
| `internal_metrics.prometheus.path` | `extensions.obi.daemon.internal_metrics.prometheus.path` | Move |
| `internal_metrics.prometheus.port` | `extensions.obi.daemon.internal_metrics.prometheus.port` | Move |
| `javaagent.attach_timeout` | `extensions.obi.capture.runtimes.java.attach_timeout` | Move |
| `javaagent.debug` | `extensions.obi.capture.runtimes.java.debug.enabled` | Move + rename |
| `javaagent.debug_instrumentation` | `extensions.obi.capture.runtimes.java.debug.bytecode_instrumentation` | Move + rename |
| `javaagent.enabled` | `extensions.obi.capture.runtimes.java.enabled` | Move |
| `log_config` | `extensions.obi.daemon.logging.config_format` | Move + rename |
| `log_format` | `extensions.obi.daemon.logging.format` | Move + rename |
| `log_level` | Top-level `log_level` | Move to standard field |
| `metrics.features` | `extensions.obi.capture.instrumentation.<protocol>.enabled.metrics` + `extensions.obi.capture.network.capture.enabled` + `extensions.obi.capture.network.stats.{enabled,features}` | Split mapping for application RED, basic network flow, and individual network-stat features only |
| `name_resolver.cache_expiry` | `extensions.obi.enrich.service_name.cache.ttl` | Move + rename |
| `name_resolver.cache_len` | `extensions.obi.enrich.service_name.cache.size` | Move + rename |
| `name_resolver.sources` | `extensions.obi.enrich.service_name.sources` | Move |
| `network.agent_ip` | `extensions.obi.capture.network.capture.endpoint_identity.agent_ip` | Move |
| `network.agent_ip_iface` | `extensions.obi.capture.network.capture.endpoint_identity.agent_ip_interface` | Move + rename |
| `network.agent_ip_type` | `extensions.obi.capture.network.capture.endpoint_identity.agent_ip_family` | Move + rename |
| `network.cache_active_timeout` | `extensions.obi.capture.network.capture.flow_lifecycle.active_timeout` | Move + rename |
| `network.cache_max_flows` | `extensions.obi.capture.network.capture.flow_lifecycle.max_tracked_flows` and `extensions.obi.capture.limits.network_packets` | Split mapping |
| `network.cidrs` | `extensions.obi.capture.network.capture.selection.cidrs` | Move |
| `network.deduper` | `extensions.obi.capture.network.capture.flow_lifecycle.deduplication.strategy` | Move + rename |
| `network.deduper_fc_ttl` | `extensions.obi.capture.network.capture.flow_lifecycle.deduplication.first_come_ttl` | Move + rename |
| `network.direction` | `extensions.obi.capture.network.capture.selection.direction` | Move |
| `network.enable` | `extensions.obi.capture.network.capture.enabled` | Move + rename |
| `network.geo_ip.cache_expiry` | `extensions.obi.capture.network.capture.enrichment.geo_ip.cache.ttl` | Move + rename |
| `network.geo_ip.cache_len` | `extensions.obi.capture.network.capture.enrichment.geo_ip.cache.size` | Move + rename |
| `network.geo_ip.ipinfo.path` | `extensions.obi.capture.network.capture.enrichment.geo_ip.ipinfo.path` | Move |
| `network.geo_ip.maxmind.asn_path` | `extensions.obi.capture.network.capture.enrichment.geo_ip.maxmind.asn_path` | Move |
| `network.geo_ip.maxmind.country_path` | `extensions.obi.capture.network.capture.enrichment.geo_ip.maxmind.country_path` | Move |
| `network.guess_ports` | `extensions.obi.capture.network.capture.flow_lifecycle.guess_ports` | Move |
| `network.listen_interfaces` | `extensions.obi.capture.network.capture.interface_discovery.mode` | Move + reshape |
| `network.listen_poll_period` | `extensions.obi.capture.network.capture.interface_discovery.poll_interval` | Move + rename |
| `network.exclude_interfaces` | `extensions.obi.capture.network.capture.selection.interfaces.exclude` | Move + reshape |
| `network.exclude_protocols` | `extensions.obi.capture.network.capture.selection.protocols.exclude` | Move + reshape |
| `network.interfaces` | `extensions.obi.capture.network.capture.selection.interfaces.include` | Move + reshape |
| `network.protocols` | `extensions.obi.capture.network.capture.selection.protocols.include` | Move + reshape |
| `network.print_flows` | `extensions.obi.capture.network.capture.diagnostics.print_flows` | Move |
| `network.reverse_dns.cache_expiry` | `extensions.obi.capture.network.capture.enrichment.reverse_dns.cache.ttl` | Move + rename |
| `network.reverse_dns.cache_len` | `extensions.obi.capture.network.capture.enrichment.reverse_dns.cache.size` | Move + rename |
| `network.reverse_dns.type` | `extensions.obi.capture.network.capture.enrichment.reverse_dns.mode` | Move + rename |
| `network.sampling` | `extensions.obi.capture.network.capture.flow_lifecycle.sampling` | Move |
| `network.source` | `extensions.obi.capture.network.capture.source` | Move |
| `nodejs.enabled` | `extensions.obi.capture.runtimes.nodejs.enabled` | Move |
| `otel_metrics_export.endpoint` | `meter_provider.readers[0].periodic.exporter.otlp_grpc.endpoint` or, with gated HTTP support, `.otlp_http.endpoint` | OTel ownership move; automatic migration emits gRPC, while HTTP requires the documented manual mapping |
| `otel_metrics_export.features` | Split through the effective `metrics.features` mapping | Deprecated; an enabled OTLP exporter whose deprecated `features` field is present (including `[]`) takes precedence, otherwise enabled Prometheus features may supply it |
| `otel_metrics_export.histogram_aggregation` | `meter_provider.readers[0].periodic.exporter.otlp_grpc.default_histogram_aggregation` | OTel ownership move + declarative reader/exporter shape |
| `otel_metrics_export.instrumentations` | `extensions.obi.capture.instrumentation.<protocol>.enabled.metrics` | Only protocols modeled by v2; migration rejects differing active OTLP and Prometheus lists |
| `otel_metrics_export.interval` | `meter_provider.readers[0].periodic.interval` | Converted to milliseconds |
| `otel_metrics_export.protocol` | Selects `meter_provider.readers[0].periodic.exporter.otlp_grpc` or, with gated HTTP support, `.otlp_http` plus its `encoding` | The exporter shape encodes the protocol; automatic migration currently supports gRPC |
| `otel_metrics_export.reporters_cache_len` | `extensions.obi.capture.telemetry.metrics.reporters_cache_len` | Move to capture telemetry tuning |
| `otel_metrics_export.ttl` | `extensions.obi.capture.telemetry.metrics.ttl` | Move to capture telemetry tuning |
| `otel_traces_export.endpoint` | `tracer_provider.processors[0].batch.exporter.otlp_grpc.endpoint` or, with gated HTTP support, `.otlp_http.endpoint` | OTel ownership move; automatic migration emits gRPC, while HTTP requires the documented manual mapping |
| `otel_traces_export.instrumentations` | `extensions.obi.capture.instrumentation.<protocol>.enabled.traces` | Only protocols modeled by v2 |
| `otel_traces_export.protocol` | Selects `tracer_provider.processors[0].batch.exporter.otlp_grpc` or, with gated HTTP support, `.otlp_http` plus its `encoding` | The exporter shape encodes the protocol; automatic migration currently supports gRPC |
| `otel_traces_export.batch_timeout` | `tracer_provider.processors[0].batch.schedule_delay` | OTel ownership move + rename + duration(ms) representation |
| `otel_traces_export.queue_size` | `tracer_provider.processors[0].batch.max_queue_size` | OTel ownership move + declarative processor list shape |
| `otel_traces_export.batch_max_size` | `tracer_provider.processors[0].batch.max_export_batch_size` | OTel ownership move + declarative processor list shape |
| `otel_traces_export.reporters_cache_len` | `extensions.obi.capture.telemetry.traces.reporters_cache_len` | Move to capture telemetry tuning |
| `otel_traces_export.sampler.arg` | `tracer_provider.sampler` | OTel ownership move for supported global built-in samplers; per-workload sampler arguments are unsupported |
| `otel_traces_export.sampler.name` | `tracer_provider.sampler` | OTel ownership move for supported global built-in samplers; per-workload samplers are unsupported |
| `profile_port` | `extensions.obi.daemon.profiling.port` | Move |
| `prometheus_export.allow_service_graph_self_references` | `extensions.obi.daemon.telemetry.metrics.prometheus.allow_service_graph_self_references` | Move to daemon telemetry tuning |
| `prometheus_export.extra_resource_attributes` | `extensions.obi.daemon.telemetry.metrics.prometheus.extra_resource_attributes` | Move to daemon telemetry tuning |
| `prometheus_export.extra_span_resource_attributes` | `extensions.obi.daemon.telemetry.metrics.prometheus.extra_span_resource_attributes` | Move to daemon telemetry tuning |
| `prometheus_export.port` | `meter_provider.readers[1].pull.exporter.prometheus/development.port` | OTel ownership move + declarative reader/exporter shape |
| `prometheus_export.path` | *No canonical OTel core path in current declarative schema* | Distribution-specific/unsupported in current target shape |
| `prometheus_export.features` | Split through the effective `metrics.features` mapping | Deprecated; used only when the OTLP metric exporter does not provide features |
| `prometheus_export.instrumentations` | `extensions.obi.capture.instrumentation.<protocol>.enabled.metrics` | Only protocols modeled by v2; migration rejects differing active Prometheus and OTLP lists |
| `prometheus_export.service_cache_size` | `extensions.obi.daemon.telemetry.metrics.prometheus.span_metrics_service_cache_size` | Move to daemon telemetry tuning + rename |
| `routes.ignore_mode` | `extensions.obi.capture.instrumentation.http.routes.{incoming,outgoing}.ignore_mode` | Move + duplicate v1 global value into both directions |
| `routes.ignored_patterns` | `extensions.obi.capture.instrumentation.http.routes.{incoming,outgoing}.ignored_patterns` | Move + duplicate v1 global value into both directions |
| `routes.max_path_segment_cardinality` | `extensions.obi.capture.instrumentation.http.routes.{incoming,outgoing}.max_path_segment_cardinality` | Move + duplicate v1 global value into both directions |
| `routes.patterns` | `extensions.obi.capture.instrumentation.http.routes.{incoming,outgoing}.patterns` | Move + duplicate v1 global value into both directions |
| `routes.unmatched` | `extensions.obi.capture.instrumentation.http.routes.{incoming,outgoing}.unmatched` | Move + duplicate v1 global value into both directions |
| `routes.wildcard_char` | `extensions.obi.capture.instrumentation.http.routes.{incoming,outgoing}.wildcard_char` | Move + duplicate v1 global value into both directions |
| `service_name` | String `resource.attributes[]` entry named `service.name` | Manual standalone mapping; automatic migration rejects the deprecated OBI-wide override |
| `service_namespace` | String `resource.attributes[]` entry named `service.namespace` | Manual standalone mapping; automatic migration rejects the deprecated OBI-wide override |
| `shutdown_timeout` | `extensions.obi.daemon.shutdown.timeout` | Move |
| `stats.agent_ip` | `extensions.obi.capture.network.stats.endpoint_identity.agent_ip` | Move |
| `stats.agent_ip_iface` | `extensions.obi.capture.network.stats.endpoint_identity.agent_ip_interface` | Move + rename |
| `stats.agent_ip_type` | `extensions.obi.capture.network.stats.endpoint_identity.agent_ip_family` | Move + rename |
| `stats.cidrs` | `extensions.obi.capture.network.stats.selection.cidrs` | Move |
| `stats.geo_ip.cache_expiry` | `extensions.obi.capture.network.stats.enrichment.geo_ip.cache.ttl` | Move + rename |
| `stats.geo_ip.cache_len` | `extensions.obi.capture.network.stats.enrichment.geo_ip.cache.size` | Move + rename |
| `stats.geo_ip.ipinfo.path` | `extensions.obi.capture.network.stats.enrichment.geo_ip.ipinfo.path` | Move |
| `stats.geo_ip.maxmind.asn_path` | `extensions.obi.capture.network.stats.enrichment.geo_ip.maxmind.asn_path` | Move |
| `stats.geo_ip.maxmind.country_path` | `extensions.obi.capture.network.stats.enrichment.geo_ip.maxmind.country_path` | Move |
| `stats.print_stats` | `extensions.obi.capture.network.stats.diagnostics.print_stats` | Move |
| `stats.reverse_dns.cache_expiry` | `extensions.obi.capture.network.stats.enrichment.reverse_dns.cache.ttl` | Move + rename |
| `stats.reverse_dns.cache_len` | `extensions.obi.capture.network.stats.enrichment.reverse_dns.cache.size` | Move + rename |
| `stats.reverse_dns.type` | `extensions.obi.capture.network.stats.enrichment.reverse_dns.mode` | Move + rename |
| `trace_printer` | `extensions.obi.daemon.logging.debug_trace_output` | Move + rename |

Both v2 paths for `network.cache_max_flows` configure the same runtime value.
Migration writes them identically. If an authored document sets both
`capture.limits.network_packets` and
`capture.network.capture.flow_lifecycle.max_tracked_flows`, they must be equal;
each explicitly authored value must also be greater than zero. Validation
rejects zero or divergent values instead of silently choosing one.

## Related docs

- Config v1 to v2 migration guide: [migration.md](migration.md)
- OBI extension schema: [obi-extension.schema.json](obi-extension.schema.json)
- Runnable standalone configuration:
  [examples/default-configuration.yaml](examples/default-configuration.yaml)
- Authored default-values reference fragment (not a standalone document):
  [examples/default-values-reference.fragment.yaml](examples/default-values-reference.fragment.yaml)
- Tested migration input and generated result:
  [examples/migration-v1.yaml](examples/migration-v1.yaml) and
  [examples/migration-v2.yaml](examples/migration-v2.yaml)
- Tested receiver migration input and generated component body:
  [examples/migration-receiver-v1.yaml](examples/migration-receiver-v1.yaml)
  and
  [examples/migration-receiver-v2.yaml](examples/migration-receiver-v2.yaml)

## Appendix: upstream alignment status (2026-02-24)

The OTel declarative schema does not currently define `extensions` as a first-class root node,
but the root schema allows additional properties and does not explicitly exclude it.

After review and discussion in upstream issues:

- [Placement discussion](https://github.com/open-telemetry/opentelemetry-configuration/issues/335)
- [OBI comment with context](https://github.com/open-telemetry/opentelemetry-configuration/issues/335#issuecomment-3954773010)
- [Ownership/overlap follow-up](https://github.com/open-telemetry/opentelemetry-configuration/issues/545)

Decision for OBI v2:

- Keep `extensions.obi` as the canonical OBI-owned configuration namespace.
- Keep top-level declarative OTel sections authoritative for pipeline semantics.
- Do not treat `instrumentation/development` as an OBI configuration source.

This is an intentional middle-ground while upstream schema guidance evolves.
OBI will support `extensions.obi` with its own parser and validation rules until a better
standardized schema location is available.
