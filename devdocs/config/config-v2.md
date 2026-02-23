# OBI Configuration Composition Draft

Status: Draft for discussion  
Audience: OBI maintainers and contributors  
Scope: configuration model, schema, validation, and migration UX

The current configuration model has evolved organically with a focus on implementation needs and incremental user feedback.
This has led to some structural inconsistencies, redundant controls, and a mix of user-facing and internal configuration in the same sections.
To address this, a user-centric redesign of the configuration schema that optimizes for common user journeys, clear ownership of concerns, and a clean separation between user-facing configuration and internal implementation details is being proposed here.

Goals:

- Define a clear, consistent configuration schema that maps directly to user intent and common use cases.
- Provide an extension to the OpenTelemetry declarative configuration model that configures OBI-specific behavior.
- Grantee a smooth migration path from the current v1 configuration shape to the new v2 shape, with clear validation and tooling support.

## Design principles

To ensure that the redesign is guided by consistent values and priorities, we define the following design principles for the configuration model, schema, validation, and migration UX.

- **Journey-first, user-mental-model first**
  - Configuration should match what users are trying to do, not internal implementation layering.
  - Structure should optimize for readability and safe default operation.

- **One concern, one place**
  - Every concern has one canonical home.
  - Avoid parallel knobs for the same behavior across sections.

- **Compatible with OpenTelemetry declarative configuartion**
  - **Top-level OTel is authoritative for pipeline semantics**
    - Exporters/processors/samplers belong to top-level declarative OTel configuration sections.
    - OBI extension config should not reintroduce a competing pipeline model.
  - **OBI-specific behavior lives under `extensions.obi`**
    - Runtime capture, selection, protocol controls, enrichment, and OBI limits are extension concerns.
    - OBI config should stay namespaced and composable.

- **Protocol-local ownership over global toggles**
  - Protocol behavior should be configured under each protocol section.
  - Enablement and filtering should be signal-scoped at the protocol/network ownership point.

- **Deterministic precedence over hidden heuristics**
  - Ordered rules should define precedence explicitly.
  - Configuration should avoid ambiguous override behavior.

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

- [Full target-shape with defaults example](./default-configuration-example.yaml) (mapped from current defaults)
- [JSONSchema](./obi-extension.schema.json) (draft schema reflecting target shape)

### High-level shape

At a high level, the target configuration shape is a standard [OpenTelemetry declarative configuration](https://github.com/open-telemetry/opentelemetry-configuration) document with a root `version` field and top-level sections for `resource`, `propagator`, `tracer_provider`, and `meter_provider`.
All OBI-specific configuration lives under `extensions.obi`, which includes user-facing controls for selection, instrumentation, network observability, enrichment, optimization, and operations.

```yaml
version: '1.0-rc.1'

resource: {}
propagator: {}
tracer_provider: {}
meter_provider: {}

extensions:
  obi:
    version: "2.0"
    selection:
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
      go:
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
      java:
        enabled: { traces: true, metrics: true }
        filters: { traces: {}, metrics: {} }
      nodejs:
        enabled: { traces: true, metrics: true }
        filters: { traces: {}, metrics: {} }

    network:
      capture: {}

    enrich:
      kubernetes: {}
      naming: {}
      attributes: {}

    operations:
      limits: {}
      capture: {}
      logging: {}
      profiling: {}
      shutdown: {}
      safety: {}
      internal_metrics: {}
```

#### `version` property

The `extensions.obi.version` field defines the version of the OBI extension schema being used. This allows the parsing and validation logic to apply the correct schema rules and migration logic based on the declared version.

#### `selection` Section

This section defines the service selection and target discovery policy for instrumentation.
It includes:

- `policy`: global selection behavior controls, such as default action for unmatched services and rule precedence strategy.
- `rules`: an ordered list of selection rules that define matching criteria and actions (include/exclude) for services.
  These rules, currently, are based on:
  - process identity
  - network identity
  - language
  - Kubernetes metadata
  - already-instrumented status.

This section is the primary user control for defining which services get instrumented by OBI, and it supports complex selection logic through ordered rules.

#### `instrumentation` Section

The `extension.obi.instrumentation` section defines protocol-specific instrumentation controls, including enablement and filtering for traces and metrics.

All protocols (HTTP, gRPC, Go, SQL, Redis, Kafka, MongoDB, Couchbase, DNS, GPU, Java, Node.js) have a consistent base structure for defining whether traces and metrics are enabled and what filters apply to each signal.
Each protocol can also have its own specific configuration subsections.
For example, SQL has `mysql` and `postgres` for driver-specific controls, HTTP has `routes.discovery` for route harvesting controls, etc.

#### `network` Section

The `extensions.obi.network` section defines how network observability is configured, including endpoint identity, selection criteria, flow lifecycle controls, interface discovery behavior, enrichment options, and diagnostics. This section is the primary user control for defining how OBI captures and processes network telemetry.

#### `enrich` Section

The `extensions.obi.enrich` section defines enrichment behavior for telemetry, including service naming policy, and general attribute enrichment rules. This section allows users to configure how OBI adds contextual information to telemetry based on various sources.

#### `operation` Section

The `extensions.obi.operations` section defines runtime and operational controls for OBI, including limits, capture behavior, logging configuration, profiling options, shutdown behavior, safety controls, and internal metrics configuration. This section is the primary user control for defining how OBI operates in production environments.

### Compatibility and mapping from v1

v2 is a structural redesign of v1, but migration is deterministic and feature-complete.
The shape changes are intentional: top-level OTel sections own pipeline semantics, while OBI-specific behavior moves under `extensions.obi`.

Important migration rules before using the table:

- Pipeline ownership moved out of OBI-local export sections:
  - `otel_metrics_export.*` and `prometheus_export.*` move to top-level `meter_provider.*`.
  - `otel_traces_export.*` (including sampler) moves to top-level `tracer_provider.*`.
- Some keys fan out or invert:
  - `filter.application` fans out to protocol+signal filter sections.
  - `filter.network` fans out to network signal filter sections.
  - `metrics.features` maps to protocol metric enablement and network capture enablement.
  - `discovery.skip_go_specific_tracers` maps to `instrumentation.go.enabled` with inverted semantics.

| v1 field | v2 canonical location | Notes |
|---|---|---|
| `attributes.kubernetes.informers_sync_timeout` | `extensions.obi.enrich.enrichers.kubernetes.informers.initial_sync_timeout` | Move |
| `attributes.kubernetes.informers_resync_period` | `extensions.obi.enrich.enrichers.kubernetes.informers.resync_period` | Move |
| `attributes.metric_span_names_limit` | `extensions.obi.operations.limits.metric_span_names` | Move + rename |
| `attributes.rename_unresolved_hosts` | `extensions.obi.enrich.service_name.unresolved_hosts.names.default` | Move |
| `channel_buffer_len` | `extensions.obi.operations.runtime.channels.buffer_len` | Move |
| `channel_send_timeout` | `extensions.obi.operations.runtime.channels.send_timeout` | Move |
| `channel_send_timeout_panic` | `extensions.obi.operations.runtime.channels.panic_on_send_timeout` | Move + rename |
| `discovery.bpf_pid_filter_off` | `extensions.obi.operations.capture.pid_filter.disabled` | Move + rename |
| `discovery.default_otlp_grpc_port` | `extensions.obi.selection.rules[].match.process.exports_otlp.port` | Move + reshape |
| `discovery.disabled_route_harvesters` | `extensions.obi.instrumentation.http.routes.discovery.disabled_languages` | Move + rename |
| `discovery.exclude_otel_instrumented_services` | `extensions.obi.selection.rules[].match.process.exports_otlp` (exclude rule) | Move + reshape |
| `discovery.excluded_linux_system_paths` | `extensions.obi.selection.rules[].match.process.exe_path_glob` (exclude rule) | Move + reshape |
| `discovery.min_process_age` | `extensions.obi.selection.policy.min_process_age` | Move |
| `discovery.route_harvester_advanced.java_harvest_delay` | `extensions.obi.instrumentation.http.routes.discovery.java.delay` | Move + rename |
| `discovery.route_harvester_timeout` | `extensions.obi.instrumentation.http.routes.discovery.timeout` | Move + rename |
| `discovery.skip_go_specific_tracers` | `extensions.obi.instrumentation.go.enabled.{traces,metrics}` | Inverted boolean mapping |
| `ebpf.batch_length` | `extensions.obi.operations.capture.batching.batch_length` | Move |
| `ebpf.batch_timeout` | `extensions.obi.operations.capture.batching.batch_timeout` | Move |
| `ebpf.bpf_fs_path` | `extensions.obi.operations.capture.bpf_filesystem.path` | Move + rename |
| `ebpf.buffer_sizes.http` | `extensions.obi.instrumentation.http.buffer_size` | Move |
| `ebpf.buffer_sizes.kafka` | `extensions.obi.instrumentation.kafka.buffer_size` | Move |
| `ebpf.buffer_sizes.mysql` | `extensions.obi.instrumentation.sql.mysql.buffer_size` | Move |
| `ebpf.buffer_sizes.postgres` | `extensions.obi.instrumentation.sql.postgres.buffer_size` | Move |
| `ebpf.dns_request_timeout` | `extensions.obi.instrumentation.dns.request_timeout` | Move |
| `ebpf.heuristic_sql_detect` | `extensions.obi.instrumentation.sql.heuristic_detect` | Move + rename |
| `ebpf.kafka_topic_uuid_cache_size` | `extensions.obi.instrumentation.kafka.topic_uuid_cache_size` | Move |
| `ebpf.log_enricher.cache_size` | `extensions.obi.instrumentation.http.log_enrichment.cache.size` | Move + rename |
| `ebpf.log_enricher.cache_ttl` | `extensions.obi.instrumentation.http.log_enrichment.cache.ttl` | Move + rename |
| `ebpf.log_enricher.async_writer_workers` | `extensions.obi.instrumentation.http.log_enrichment.async_writer.workers` | Move + rename |
| `ebpf.log_enricher.async_writer_channel_len` | `extensions.obi.instrumentation.http.log_enrichment.async_writer.channel_len` | Move + rename |
| `ebpf.max_transaction_time` | `extensions.obi.operations.capture.transactions.max_duration` | Move + rename |
| `ebpf.mysql_prepared_statements_cache_size` | `extensions.obi.instrumentation.sql.mysql.prepared_statements_cache_size` | Move |
| `ebpf.payload_extraction.http.graphql.enabled` | `extensions.obi.instrumentation.http.payload_extraction.graphql.enabled` | Move |
| `ebpf.payload_extraction.http.sqlpp.enabled` | `extensions.obi.instrumentation.http.payload_extraction.sqlpp.enabled` | Move |
| `ebpf.postgres_prepared_statements_cache_size` | `extensions.obi.instrumentation.sql.postgres.prepared_statements_cache_size` | Move |
| `ebpf.redis_db_cache.enabled` | `extensions.obi.instrumentation.redis.db_cache.enabled` | Move |
| `ebpf.traffic_control_backend` | `extensions.obi.operations.capture.traffic.control_backend` | Move + rename |
| `ebpf.wakeup_len` | `extensions.obi.operations.capture.batching.wakeup_len` | Move |
| `enforce_sys_caps` | `extensions.obi.operations.safety.enforce_system_capabilities` | Move + rename |
| `filter.application` | `extensions.obi.instrumentation.<protocol>.filters.{traces,metrics}` | Fan-out to all protocols/signals |
| `filter.network` | `extensions.obi.network.capture.filters.{traces,metrics}` | Fan-out to both signals |
| `internal_metrics.bpf_metric_scrape_interval` | `extensions.obi.operations.internal_metrics.bpf.scrape_interval` | Move + rename |
| `internal_metrics.exporter` | `extensions.obi.operations.internal_metrics.exporter` | Move |
| `internal_metrics.prometheus.path` | `extensions.obi.operations.internal_metrics.prometheus.path` | Move |
| `javaagent.attach_timeout` | `extensions.obi.instrumentation.java.attach_timeout` | Move |
| `javaagent.debug` | `extensions.obi.instrumentation.java.debug.enabled` | Move + rename |
| `javaagent.debug_instrumentation` | `extensions.obi.instrumentation.java.debug.bytecode_instrumentation` | Move + rename |
| `javaagent.enabled` | `extensions.obi.instrumentation.java.enabled.{traces,metrics}` | Fan-out to both signals |
| `log_config` | `extensions.obi.operations.logging.startup_dump` | Move + rename |
| `log_level` | `extensions.obi.operations.logging.level` | Move |
| `metrics.features` | `extensions.obi.instrumentation.<protocol>.enabled.metrics` + `extensions.obi.network.capture.enabled` | Split mapping |
| `name_resolver.cache_expiry` | `extensions.obi.enrich.service_name.cache.ttl` | Move + rename |
| `name_resolver.cache_len` | `extensions.obi.enrich.service_name.cache.size` | Move + rename |
| `network.agent_ip` | `extensions.obi.network.capture.endpoint_identity.agent_ip` | Move |
| `network.agent_ip_iface` | `extensions.obi.network.capture.endpoint_identity.agent_ip_interface` | Move + rename |
| `network.agent_ip_type` | `extensions.obi.network.capture.endpoint_identity.agent_ip_family` | Move + rename |
| `network.cache_active_timeout` | `extensions.obi.network.capture.flow_lifecycle.active_timeout` | Move + rename |
| `network.cache_max_flows` | `extensions.obi.network.capture.flow_lifecycle.max_tracked_flows` | Move + rename |
| `network.deduper` | `extensions.obi.network.capture.flow_lifecycle.deduplication.strategy` | Move + rename |
| `network.deduper_fc_ttl` | `extensions.obi.network.capture.flow_lifecycle.deduplication.first_come_ttl` | Move + rename |
| `network.direction` | `extensions.obi.network.capture.selection.direction` | Move |
| `network.enable` | `extensions.obi.network.capture.enabled` | Move + rename |
| `network.geo_ip.cache_expiry` | `extensions.obi.network.capture.enrichment.geo_ip.cache.ttl` | Move + rename |
| `network.listen_interfaces` | `extensions.obi.network.capture.interface_discovery.mode` | Move + reshape |
| `network.listen_poll_period` | `extensions.obi.network.capture.interface_discovery.poll_interval` | Move + rename |
| `network.print_flows` | `extensions.obi.network.capture.diagnostics.print_flows` | Move |
| `network.reverse_dns.cache_expiry` | `extensions.obi.network.capture.enrichment.reverse_dns.cache.ttl` | Move + rename |
| `network.sampling` | `extensions.obi.network.capture.flow_lifecycle.sampling` | Move |
| `network.source` | `extensions.obi.network.capture.source` | Move |
| `nodejs.enabled` | `extensions.obi.instrumentation.nodejs.enabled.{traces,metrics}` | Fan-out to both signals |
| `otel_metrics_export.histogram_aggregation` | `meter_provider.views.histogram_aggregation` | OTel ownership move |
| `otel_metrics_export.reporters_cache_len` | `meter_provider.reporters_cache_len` | OTel ownership move |
| `otel_metrics_export.ttl` | `meter_provider.ttl` | OTel ownership move |
| `otel_traces_export.batch_timeout` | `tracer_provider.processors.batch.timeout` | OTel ownership move |
| `otel_traces_export.max_queue_size` | `tracer_provider.processors.batch.max_queue_size` | OTel ownership move |
| `otel_traces_export.reporters_cache_len` | `tracer_provider.reporters_cache_len` | OTel ownership move |
| `otel_traces_export.sampler.arg` | `tracer_provider.sampler.arg` | OTel ownership move |
| `otel_traces_export.sampler.name` | `tracer_provider.sampler.name` | OTel ownership move |
| `profile_port` | `extensions.obi.operations.profiling.port` | Move |
| `prometheus_export.path` | `meter_provider.readers.prometheus.path` | OTel ownership move |
| `prometheus_export.service_cache_size` | `meter_provider.span_metrics_service_cache_size` | OTel ownership move + rename |
| `routes.max_path_segment_cardinality` | `extensions.obi.instrumentation.http.routes.max_path_segment_cardinality` | Move |
| `routes.unmatched` | `extensions.obi.instrumentation.http.routes.unmatched` | Move |
| `routes.wildcard_char` | `extensions.obi.instrumentation.http.routes.wildcard_char` | Move |
| `shutdown_timeout` | `extensions.obi.operations.shutdown.timeout` | Move |
| `trace_printer` | `extensions.obi.operations.logging.debug_trace_output` | Move + rename |

## Capability-Based Applicability Matrix

Legend: **A** = Allowed, **I** = Ignored (warning), **F** = Forbidden (validation error)

| Section | Standalone host capability | Collector receiver capability |
|---|---:|---:|
| `extensions.obi.selection|instrumentation|network|enrich|operations` | A | A |
| top-level `tracer_provider|meter_provider|resource|propagator` | A | A |
| Legacy OBI exporter keys (`otel_*_export`, `prometheus_export`, `trace_printer`) | I (migration only) | F |
| Collector pipeline/exporters (collector config) | I | A |

Notes:

- In receiver capability, extraneous OBI exporter/processing config is invalid by design.
- DaemonSet vs non-DaemonSet deployment is runtime topology and MUST NOT be encoded as a config mode.

## Validation Contract in Practice

Validation is two-stage:

1. Base schema validation
   - Validate structure, types, and required fields of the composable schema.

2. Capability validation (host-provided)
   - Host supplies capability set (`standalone_host` or `collector_receiver`).
   - Validator enforces applicability matrix and rejects forbidden sections.

Required behavior:

- `obi --config` MUST validate with `standalone_host` capability.
- OBI Collector receiver MUST validate with `collector_receiver` capability.
- In `collector_receiver` capability:
  - legacy OBI exporter keys MUST fail as extraneous,
  - OBI-local exporter aliases MUST fail where collector pipelines are authoritative.

Example receiver errors:

- `otel_traces_export` is extraneous for OBI receiver; configure processors/exporters in Collector pipelines.
- `otel_metrics_export` is extraneous for OBI receiver; configure exporters in Collector pipelines.

## Validation and Tooling Plan

1. Schema layer
   - Maintain one composable base schema for structure and types.

2. Capability layer
   - Apply host-provided capability rules after schema validation.
   - Keep applicability rules explicit and testable.

3. Runtime guardrails
   - Receiver startup MUST enforce forbidden-section checks even if schema gating is bypassed.

4. Migration CLI
   - `obi config migrate --from v1 --to v2` rewrites keys to canonical locations.

- For legacy export keys, rewrite to top-level declarative pipeline sections where deterministic; otherwise fail with actionable guidance.

5. Docs
   - Provide two composition views:

- standalone: `extensions.obi.*` extension + top-level declarative pipeline sections
- receiver: `extensions.obi.*` extension + collector-owned pipeline sections

## Migration Program (v1 → v2)

This section defines the end-to-end migration path and aligns with the proposed sequence.

### Phase 0: Freeze and identify v1

- v1 key surface SHOULD be treated as frozen except for critical fixes.
- v2 files MUST include root `version` (OTel declarative doc format) and SHOULD include `extensions.obi.version` (OBI extension schema format).
- Loader behavior SHOULD be two-stage:
  1. Parse/validate root OTel declarative document using top-level `version`.
  2. Parse `extensions.obi` using `extensions.obi.version`.
- Backward compatibility behavior SHOULD be:
  - if root `version` indicates declarative format and `extensions.obi.version` exists/supported: parse OBI extension with that version,
  - if root `version` indicates declarative format and `extensions.obi.version` is absent: treat OBI extension as legacy-v1-compatible shape and apply compatibility translation,
  - if root `version` is absent: parse as legacy v1,
  - if either declared format is unsupported: fail with actionable version guidance.
- We SHOULD NOT add a mandatory new header to legacy v1; absence of `version` remains a supported discriminator during migration.

### Phase 1: Build v2 contract and tooling

- v2 schema MUST be authored as the source-of-truth model and compiled to JSON Schema artifacts.
- Generated artifacts MUST include:
  - validation schema,
  - human docs,
  - examples/snippets,
  - capability rule definitions.
- Loader plumbing MUST support v2 parse + validation in both standalone and receiver hosts.

### Phase 2: Dual-read and migration tooling

- Runtime MUST support both v1 and v2 during transition.
- `obi config migrate` MUST:
  - read v1,
  - emit v2,
  - emit mapping report/warnings,
  - fail only when rewrite is non-deterministic and requires user decision.
- Receiver host MUST enforce capability validation for both v1 and v2 inputs (with v1 compatibility aliases translated first).

### Phase 3: Deprecation and v2-only

- Deprecation policy SHOULD define explicit release-based gates, for example:
  - N: v2 GA, v1 supported with warnings,
  - N+1: stricter warnings + CI/docs default to v2,
  - N+2 (or policy-defined): v1 parsing removed.
- Removal gates MUST include:
  - migration tool coverage for major v1 patterns,
  - published migration guide,
  - telemetry/evidence that remaining v1 usage is low enough.

### Backward compatibility behavior during transition

- Standalone host:
  - v1 accepted (with migration warnings), v2 accepted.
- Receiver host:
  - v1 accepted only through compatibility translation + capability validation.
  - extraneous exporter/processing config remains invalid per receiver policy.

## Open Questions for Review

1. In receiver capability, should legacy OBI exporter aliases be hard-fail immediately or phased warn → fail?
2. How strict should standalone migration be when legacy exporter keys cannot be mapped 1:1 to top-level declarative pipeline sections?
3. Should `obi.operations.internal_metrics` remain partially allowed in receiver capability or be fully delegated to Collector telemetry?
4. How long should legacy aliases remain after migration tooling is available?
5. What exact release cadence should be used for v1 freeze, v2 GA, and v1 removal?

## Proposed Next Increment

- Lock two-stage format detection contract:
  - root `version` selects OTel declarative document contract,
  - `extensions.obi.version` selects OBI extension contract,
  - absent `extensions.obi.version` under declarative root triggers legacy OBI compatibility translation.
- Lock canonical section names and capability matrix.
- Lock policy that top-level declarative sections are the single user-facing export/pipeline authority.
- Implement first migration pass for:
  - legacy export keys → top-level declarative pipeline sections,
  - legacy discovery aliases,
  - legacy target selector aliases.
- Add CI checks for:
  - v2 schema validity,
  - v1→v2 migration golden tests,
  - receiver capability rejection of extraneous sections.

## Artifacts

- OBI extension schema artifact: [devdocs/config/obi-extension.schema.json](devdocs/config/obi-extension.schema.json)
  - Scope: validates `extensions.obi` for authored v2 shape (`extensions.obi.version: "2.0"`).
