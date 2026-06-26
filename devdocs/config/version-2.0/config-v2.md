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
  - The receiver-valid sub-config should be embeddable directly, without requiring users to manually extract a subset.
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

- [Full default-values example](./examples/default-configuration.yaml) (all fields mapped from current defaults)
- [JSON Schema](./obi-extension.schema.json) (schema for `extensions.obi`)

### High-level shape

At a high level, the target configuration shape is a standard [OpenTelemetry declarative configuration](https://github.com/open-telemetry/opentelemetry-configuration) document with a root `file_format` field and top-level sections for `resource`, `propagator`, `tracer_provider`, and `meter_provider`.
All OBI-specific configuration lives under `extensions.obi`.

The root `file_format` follows the declarative schema version (`major.minor`), not the upstream release tag. For the current stable declarative shape, the correct value is `file_format: "1.0"` rather than `1.0.0`, `1.0.0-rc.3`, or `1.0.0-rc.1`.

The `extensions.obi` block is divided by deployment scope:

- `capture`: valid in **all** deployment modes. Contains everything OBI needs to select workloads and capture telemetry. When running OBI as a Collector receiver, this block is embedded directly in the receiver configuration — no manual extraction required.
- `enrich`, `correlation`, `daemon`: **standalone-mode only**. These sections are not valid in Collector receiver deployments. The Collector pipeline handles enrichment (via processors) and process lifecycle (logging, profiling, shutdown) in receiver mode.

```yaml
file_format: '1.0'

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
      instrumentation:
        http:
          enabled: { traces: true, metrics: true }
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

    daemon:
      logging: {}
      profiling: {}
      shutdown: {}
      internal_metrics: {}
      telemetry: {}
```

### `version` property

The `extensions.obi.version` field defines the version of the OBI extension schema being used.
This allows the parsing and validation logic to apply the correct schema rules and migration logic based on the declared version.

### `capture` Section

The `extensions.obi.capture` section is the receiver-embeddable core of the OBI configuration.
It defines what OBI instruments and how it captures telemetry.
This is the **only** section valid in Collector receiver deployments.

#### Why `capture` is a named grouping

Early design iterations kept all top-level OBI sections flat: `selection`, `instrumentation`, `runtimes`, `network`, `operations`, `enrich`, `correlation`.
The `capture` grouping was introduced for two reasons:

1. **Receiver embedding**: OBI runs in two deployment modes — standalone daemon and Collector receiver. In receiver mode, OBI is a telemetry source only. Side-effect features (k8s enrichment, log annotation) and process management (logging, profiling, shutdown) are not the receiver's responsibility — the Collector pipeline handles those. Having a single named block (`capture`) that represents exactly what the receiver embeds makes the boundary unambiguous and avoids requiring users or tools to manually enumerate which fields are valid.

2. **Correctness over documentation**: An alternative was a flat structure with a `deployment: standalone | receiver` flag, where the parser would reject standalone-only fields in receiver mode. This was rejected because it makes the boundary a runtime enforcement concern rather than a structural schema concern. With `capture` as an explicit block, the schema itself communicates the boundary, and a schema-only view of the Collector receiver config is the `capture` block — no validation flags needed.

`capture` contains:

- `policy`: global rule evaluation behavior (default action, match order, timing).
- `rules`: ordered workload selection rules (include/exclude by process identity, Kubernetes metadata, etc.).
- `instrumentation`: protocol-specific capture controls (HTTP, gRPC, SQL, Redis, Kafka, MongoDB, Couchbase, DNS, GPU).
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
- Legacy regex selectors from `discovery.services`, `discovery.exclude_services`, `executable_path`, and `open_port` become include/exclude rules with `*_regex` match fields.
- Default excludes and already-instrumented-service detection become explicit exclude rules.

Known `match.process` fields exported today:

| v2 field | Value shape | Source |
|---|---|---|
| `open_ports` | String int/range list, for example `"8080,9090-9091"` | v1 `open_ports` / `open_port` |
| `target_pids` | Integer array | v1 `target_pids` |
| `language_glob` | String array | v1 glob `languages` |
| `language_regex` | String regex | legacy v1 regex `languages` |
| `cmd_args_glob` | String array | v1 glob `cmd_args` |
| `cmd_args_regex` | String regex | legacy v1 regex `cmd_args` |
| `exe_path_glob` | String array | v1 glob `exe_path` and excluded system paths |
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
- `http.routes`: define direction-scoped custom HTTP route patterns for this workload.
- `http.filters`: replace HTTP trace/metric filters for this workload.

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
            outgoing:
              patterns:
                - /inventory/{id}
```

`incoming` applies to HTTP requests handled by the matched workload, equivalent to v1 `routes.incoming`.
`outgoing` applies to HTTP requests made by the matched workload, equivalent to v1 `routes.outgoing`.

Sampling overrides are **not** part of the `refine` block.
Per-workload sampling is handled via `tracer_provider.sampler` using the `obi_rule_based` custom sampler, which matches on resource attributes.
See the [Sampling model](#sampling-model) section below.

### Sampling model

Sampling remains owned by top-level OTel declarative configuration under `tracer_provider.sampler`.
OBI does not define a parallel sampling section under `extensions.obi`, and selection rules do not override sampler behavior.

**Why sampling is not in `capture.rules[].refine`**

The `tracer_provider.sampler` is already the standard, extensible place for sampling policy in OTel declarative config.
Adding a parallel `sampler` field inside `capture.rules[].refine` would violate the "compatible with OTel declarative configuration" principle by introducing a competing pipeline model.
Instead, the `obi_rule_based` custom sampler plugin (a planned v2 deliverable) allows workload-matching sampling behavior to be expressed inside `tracer_provider.sampler`, keeping the concern in its canonical location while still meeting the per-workload use case.

For v2 scope, OBI will provide and ship an OBI sampler plugin implementation in this project,
so users can reference it directly from `tracer_provider.sampler`.

When workload-specific sampling behavior is needed, users should configure it through the sampler itself:

- Use built-in OTel samplers when global behavior is sufficient.
- Use the `obi_rule_based` custom sampler plugin when rule/pattern-based workload sampling is required.

The plugin implementation will include:

- sampler component implementation in OBI,
- registration/wiring in OBI runtime initialization,
- validation/documentation for supported sampler rule semantics.

This keeps concerns separated and explicit:

- `extensions.obi.capture`: workload discovery and capture configuration.
- `tracer_provider.sampler`: trace sampling policy.

Example (global built-in sampler):

```yaml
tracer_provider:
  sampler:
    parent_based:
      root:
        trace_id_ratio_based:
          ratio: 0.10
```

Example (custom sampler plugin with workload-matching semantics):

```yaml
tracer_provider:
  sampler:
    obi_rule_based:
      fallback:
        always_on: {}
      rules:
        - match:
            attributes:
              service.namespace:
                - low-priority
          sample:
            trace_id_ratio_based:
              ratio: 0.01
        - match:
            attributes:
              service.name:
                - checkout
          sample:
            always_on: {}
```

### `capture.instrumentation` Section

The `capture.instrumentation` section defines protocol-specific instrumentation controls, including enablement and filtering for traces and metrics.

All protocols (HTTP, gRPC, SQL, Redis, Kafka, MongoDB, Couchbase, DNS, GPU) have a consistent base structure for defining whether traces and metrics are enabled and what filters apply to each signal.
Each protocol can also have its own specific configuration subsections.
For example, SQL has `mysql` and `postgres` for driver-specific controls, HTTP has `routes.discovery` for route harvesting controls, etc.

HTTP `payload_extraction` uses the same list-based enablement model as other instrumentation selectors:

- `payload_extraction.enabled` is the only enablement surface.
- Concrete values currently supported are `graphql`, `elasticsearch`, `aws`, `sqlpp`, `openai`, `anthropic`, `gemini`, `qwen`, `bedrock`, `mcp`, `embedding`, `rerank`, `retrieval`, `jsonrpc`, and `enrichment`.
- Nested extractor blocks are for tuning, not duplicate enablement. For example, `payload_extraction.sqlpp.endpoint_patterns` refines SQL++ matching after `sqlpp` is enabled in the list.
- If future aliases or families are needed, they should be added as values in the same `enabled` list rather than introducing parallel knobs.

### `capture.runtimes` Section

The `capture.runtimes` section defines how language-specific runtime instrumentation injection mechanisms are controlled.
These include Go probes, Node.js SIGUSR1 signal injection, and Java agent attachment.

Unlike protocol instrumentation, runtimes are not about capturing specific telemetry signals — they are about *how* to instrument a service once it's selected.
Each runtime has a simple structure: `enabled` (boolean) controls whether to attempt injection, and `filter` provides optional per-runtime refinement for which selected services receive the injection.
Java also includes additional runtime-specific configuration such as debug controls and attachment timeout.

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

For Kubernetes environments using OBI as a receiver, use `k8sattributesprocessor` and set `enrich.enrichers.kubernetes.mode: disabled` if the `enrich` section is present (or omit `enrich` entirely):

```yaml
extensions:
  obi:
    enrich:
      enrichers:
        kubernetes:
          mode: disabled   # use k8sattributesprocessor in the Collector pipeline instead
```

The `mode` field supports: `autodetect` (default — enable if k8s environment is detected), `enabled`, and `disabled`.

### `correlation` Section

The `extensions.obi.correlation` section defines trace-context correlation features that propagate OBI-generated trace context into external streams.
Unlike telemetry instrumentation (protocol signals), correlation features operate *after* traces are captured to enrich related observability data.

For example, `log_trace_annotation` allows trace context to be injected into application logs from selected services, linking logs to traces through context correlation.

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

- `logging`: OBI process log level, format, startup configuration output format, and debug trace output mode.
- `profiling`: optional pprof endpoint for the OBI process.
- `shutdown`: graceful shutdown timeout.
- `internal_metrics`: OBI daemon's own metrics export (Prometheus or OTLP).
- `telemetry.metrics.prometheus`: Prometheus-exporter-specific metric shaping for OBI standalone output.

### Compatibility and mapping from v1

v2 is a structural redesign of v1, with deterministic compatibility mapping.
Use the table below to find any v1 field and its v2 canonical location.

Important mapping notes:

- OTel pipeline structure ownership moved to top-level declarative sections:
  - `otel_metrics_export` pipeline structure and transport settings → `meter_provider.*`
  - `prometheus_export.path` → `meter_provider.*`
  - `otel_traces_export` pipeline structure and transport/sampler settings → `tracer_provider.*`
- The old flat `operations` section is split by deployment scope:
  - Capture-valid fields move into `extensions.obi.capture.*` (valid in all deployment modes).
  - Daemon-only fields move into `extensions.obi.daemon.*` (standalone mode only).
- Some mappings are non-1:1:
  - `filter.application` fans out to `capture.instrumentation.<protocol>.filters.{traces,metrics}`.
  - `filter.network` fans out to `capture.network.capture.filters.{traces,metrics}`.
  - `filter.stats` fans out to `capture.network.stats.filters.{traces,metrics}`.
  - `metrics.features` maps to `capture.instrumentation.<protocol>.enabled.metrics`, `capture.network.capture.enabled`, and `capture.network.stats.{enabled,features}`.
  - Discovery selectors are exported as effective `capture.rules` after legacy/new selector precedence is resolved.
  - `discovery.skip_go_specific_tracers` maps to `capture.runtimes.go.enabled` with inverted semantics.

| v1 field | v2 canonical location | Notes |
|---|---|---|
| `attributes.kubernetes.informers_sync_timeout` | `extensions.obi.enrich.enrichers.kubernetes.informers.initial_sync_timeout` | Move |
| `attributes.kubernetes.informers_resync_period` | `extensions.obi.enrich.enrichers.kubernetes.informers.resync_period` | Move |
| `attributes.metric_span_names_limit` | `extensions.obi.capture.limits.metric_span_names` | Move + rename |
| `attributes.rename_unresolved_hosts` | `extensions.obi.enrich.service_name.unresolved_hosts.names.default` | Move |
| `channel_buffer_len` | `extensions.obi.capture.channels.buffer_len` | Move |
| `channel_send_timeout` | `extensions.obi.capture.channels.send_timeout` | Move |
| `channel_send_timeout_panic` | `extensions.obi.capture.channels.panic_on_send_timeout` | Move + rename |
| `discovery.bpf_pid_filter_off` | `extensions.obi.capture.engine.pid_filter.disabled` | Move + rename |
| `discovery.default_otlp_grpc_port` | `extensions.obi.capture.rules[].match.process.exports_otlp.port` | Move + reshape |
| `discovery.default_exclude_instrument` | `extensions.obi.capture.rules[]` (exclude rules with glob selectors) | Move + reshape |
| `discovery.default_exclude_services` | `extensions.obi.capture.rules[]` (exclude rules with legacy regex selectors) | Legacy move + reshape |
| `discovery.disabled_route_harvesters` | `extensions.obi.capture.instrumentation.http.routes.discovery.disabled_languages` | Move + rename |
| `discovery.exclude_instrument` | `extensions.obi.capture.rules[]` (exclude rules with glob selectors) | Move + reshape |
| `discovery.exclude_otel_instrumented_services` | `extensions.obi.capture.rules[].match.process.exports_otlp` (exclude rule) | Move + reshape |
| `discovery.exclude_services` | `extensions.obi.capture.rules[]` (exclude rules with legacy regex selectors) | Legacy move + reshape |
| `discovery.excluded_linux_system_paths` | `extensions.obi.capture.rules[].match.process.exe_path_glob` (exclude rule) | Move + reshape |
| `discovery.instrument` | `extensions.obi.capture.rules[]` (include rules with glob selectors) | Move + reshape |
| `discovery.min_process_age` | `extensions.obi.capture.policy.min_process_age` | Move |
| `discovery.route_harvester_advanced.java_harvest_delay` | `extensions.obi.capture.instrumentation.http.routes.discovery.java.delay` | Move + rename |
| `discovery.route_harvester_timeout` | `extensions.obi.capture.instrumentation.http.routes.discovery.timeout` | Move + rename |
| `discovery.services` | `extensions.obi.capture.rules[]` (include rules with legacy regex selectors) | Legacy move + reshape |
| `discovery.skip_go_specific_tracers` | `extensions.obi.capture.runtimes.go.enabled` | Inverted boolean mapping |
| `ebpf.batch_length` | `extensions.obi.capture.engine.batching.batch_length` | Move |
| `ebpf.batch_timeout` | `extensions.obi.capture.engine.batching.batch_timeout` | Move |
| `ebpf.bpf_fs_path` | `extensions.obi.capture.engine.bpf_filesystem.path` | Move + rename |
| `ebpf.buffer_sizes.http` | `extensions.obi.capture.instrumentation.http.buffer_size` | Move |
| `ebpf.buffer_sizes.kafka` | `extensions.obi.capture.instrumentation.kafka.buffer_size` | Move |
| `ebpf.buffer_sizes.mssql` | `extensions.obi.capture.instrumentation.sql.mssql.buffer_size` | Move |
| `ebpf.buffer_sizes.mysql` | `extensions.obi.capture.instrumentation.sql.mysql.buffer_size` | Move |
| `ebpf.buffer_sizes.postgres` | `extensions.obi.capture.instrumentation.sql.postgres.buffer_size` | Move |
| `ebpf.dns_request_timeout` | `extensions.obi.capture.instrumentation.dns.request_timeout` | Move |
| `ebpf.force_bpf_map_reader` | `extensions.obi.capture.engine.traffic.force_map_reader` | Move + rename |
| `ebpf.heuristic_sql_detect` | `extensions.obi.capture.instrumentation.sql.heuristic_detect` | Move + rename |
| `ebpf.kafka_topic_uuid_cache_size` | `extensions.obi.capture.instrumentation.kafka.topic_uuid_cache_size` | Move |
| `ebpf.log_enricher.cache_size` | `extensions.obi.correlation.log_trace_annotation.cache.size` | Move + rename |
| `ebpf.log_enricher.cache_ttl` | `extensions.obi.correlation.log_trace_annotation.cache.ttl` | Move + rename |
| `ebpf.log_enricher.async_writer_workers` | `extensions.obi.correlation.log_trace_annotation.async_writer.workers` | Move + rename |
| `ebpf.log_enricher.async_writer_channel_len` | `extensions.obi.correlation.log_trace_annotation.async_writer.channel_len` | Move + rename |
| `ebpf.maps_config.global_scale_factor` | `extensions.obi.capture.engine.maps.global_scale_factor` | Move + rename |
| `ebpf.max_transaction_time` | `extensions.obi.capture.engine.transactions.max_duration` | Move + rename |
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
| `ebpf.redis_db_cache.enabled` | `extensions.obi.capture.instrumentation.redis.db_cache.enabled` | Move |
| `ebpf.traffic_control_backend` | `extensions.obi.capture.engine.traffic.control_backend` | Move + rename |
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
| `javaagent.attach_timeout` | `extensions.obi.capture.runtimes.java.attach_timeout` | Move |
| `javaagent.debug` | `extensions.obi.capture.runtimes.java.debug.enabled` | Move + rename |
| `javaagent.debug_instrumentation` | `extensions.obi.capture.runtimes.java.debug.bytecode_instrumentation` | Move + rename |
| `javaagent.enabled` | `extensions.obi.capture.runtimes.java.enabled` | Simplified to boolean |
| `log_config` | `extensions.obi.daemon.logging.config_format` | Move + rename |
| `log_format` | `extensions.obi.daemon.logging.format` | Move + rename |
| `log_level` | `extensions.obi.daemon.logging.level` | Move |
| `metrics.features` | `extensions.obi.capture.instrumentation.<protocol>.enabled.metrics` + `extensions.obi.capture.network.capture.enabled` + `extensions.obi.capture.network.stats.{enabled,features}` | Split mapping |
| `name_resolver.cache_expiry` | `extensions.obi.enrich.service_name.cache.ttl` | Move + rename |
| `name_resolver.cache_len` | `extensions.obi.enrich.service_name.cache.size` | Move + rename |
| `network.agent_ip` | `extensions.obi.capture.network.capture.endpoint_identity.agent_ip` | Move |
| `network.agent_ip_iface` | `extensions.obi.capture.network.capture.endpoint_identity.agent_ip_interface` | Move + rename |
| `network.agent_ip_type` | `extensions.obi.capture.network.capture.endpoint_identity.agent_ip_family` | Move + rename |
| `network.cache_active_timeout` | `extensions.obi.capture.network.capture.flow_lifecycle.active_timeout` | Move + rename |
| `network.cache_max_flows` | `extensions.obi.capture.network.capture.flow_lifecycle.max_tracked_flows` | Move + rename |
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
| `network.print_flows` | `extensions.obi.capture.network.capture.diagnostics.print_flows` | Move |
| `network.reverse_dns.cache_expiry` | `extensions.obi.capture.network.capture.enrichment.reverse_dns.cache.ttl` | Move + rename |
| `network.reverse_dns.cache_len` | `extensions.obi.capture.network.capture.enrichment.reverse_dns.cache.size` | Move + rename |
| `network.reverse_dns.type` | `extensions.obi.capture.network.capture.enrichment.reverse_dns.mode` | Move + rename |
| `network.sampling` | `extensions.obi.capture.network.capture.flow_lifecycle.sampling` | Move |
| `network.source` | `extensions.obi.capture.network.capture.source` | Move |
| `nodejs.enabled` | `extensions.obi.capture.runtimes.nodejs.enabled` | Simplified to boolean |
| `otel_metrics_export.histogram_aggregation` | `meter_provider.readers[0].periodic.exporter.otlp_grpc.default_histogram_aggregation` | OTel ownership move + declarative reader/exporter shape |
| `otel_metrics_export.reporters_cache_len` | `extensions.obi.capture.telemetry.metrics.reporters_cache_len` | Move to capture telemetry tuning |
| `otel_metrics_export.ttl` | `extensions.obi.capture.telemetry.metrics.ttl` | Move to capture telemetry tuning |
| `otel_metrics_export.extra_span_resource_attributes` | `extensions.obi.daemon.telemetry.metrics.prometheus.extra_span_resource_attributes` | Move to daemon telemetry tuning |
| `otel_traces_export.batch_timeout` | `tracer_provider.processors[0].batch.schedule_delay` | OTel ownership move + rename + duration(ms) representation |
| `otel_traces_export.queue_size` | `tracer_provider.processors[0].batch.max_queue_size` | OTel ownership move + declarative processor list shape |
| `otel_traces_export.batch_max_size` | `tracer_provider.processors[0].batch.max_export_batch_size` | OTel ownership move + declarative processor list shape |
| `otel_traces_export.reporters_cache_len` | `extensions.obi.capture.telemetry.traces.reporters_cache_len` | Move to capture telemetry tuning |
| `otel_traces_export.sampler.arg` | `tracer_provider.sampler` | OTel ownership move. Map to built-in sampler arguments when possible; per-workload semantics require the `obi_rule_based` sampler plugin. |
| `otel_traces_export.sampler.name` | `tracer_provider.sampler` | OTel ownership move. Map to built-in sampler names when possible; per-workload semantics require the `obi_rule_based` sampler plugin. |
| `profile_port` | `extensions.obi.daemon.profiling.port` | Move |
| `prometheus_export.allow_service_graph_self_references` | `extensions.obi.daemon.telemetry.metrics.prometheus.allow_service_graph_self_references` | Move to daemon telemetry tuning |
| `prometheus_export.extra_resource_attributes` | `extensions.obi.daemon.telemetry.metrics.prometheus.extra_resource_attributes` | Move to daemon telemetry tuning |
| `prometheus_export.extra_span_resource_attributes` | `extensions.obi.daemon.telemetry.metrics.prometheus.extra_span_resource_attributes` | Move to daemon telemetry tuning |
| `prometheus_export.port` | `meter_provider.readers[1].pull.exporter.prometheus/development.port` | OTel ownership move + declarative reader/exporter shape |
| `prometheus_export.path` | *No canonical OTel core path in current declarative schema* | Distribution-specific/unsupported in current target shape |
| `prometheus_export.service_cache_size` | `extensions.obi.daemon.telemetry.metrics.prometheus.span_metrics_service_cache_size` | Move to daemon telemetry tuning + rename |
| `routes.max_path_segment_cardinality` | `extensions.obi.capture.instrumentation.http.routes.max_path_segment_cardinality` | Move |
| `routes.unmatched` | `extensions.obi.capture.instrumentation.http.routes.unmatched` | Move |
| `routes.wildcard_char` | `extensions.obi.capture.instrumentation.http.routes.wildcard_char` | Move |
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

## Related docs

- Migration, validation, and tooling plan: [migration.md](migration.md)
- OBI extension schema: [obi-extension.schema.json](obi-extension.schema.json)
- Default configuration example: [examples/default-configuration.yaml](examples/default-configuration.yaml)

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
