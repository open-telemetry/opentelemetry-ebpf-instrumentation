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
- Guarantee a smooth migration path from the current v1 configuration shape to the new v2 shape, with clear validation and tooling support.

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

At a high level, the target configuration shape is a standard [OpenTelemetry declarative configuration](https://github.com/open-telemetry/opentelemetry-configuration) document with a root `file_format` field and top-level sections for `resource`, `propagator`, `tracer_provider`, and `meter_provider`.
All OBI-specific configuration lives under `extensions.obi`, which includes user-facing controls for selection, instrumentation, runtime injection, network observability, enrichment, correlation, and operations.

```yaml
file_format: '1.0-rc.1'

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

    correlation:
      log_trace_annotation:
        enabled: false
        filter: {}

    network:
      capture: {}

    enrich:
      kubernetes: {}
      naming: {}
      attributes: {}

    operations:
      limits: {}
      telemetry: {}
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

All protocols (HTTP, gRPC, SQL, Redis, Kafka, MongoDB, Couchbase, DNS, GPU) have a consistent base structure for defining whether traces and metrics are enabled and what filters apply to each signal.
Each protocol can also have its own specific configuration subsections.
For example, SQL has `mysql` and `postgres` for driver-specific controls, HTTP has `routes.discovery` for route harvesting controls, etc.

#### `runtimes` Section

The `extensions.obi.runtimes` section defines how language-specific runtime instrumentation injection mechanisms are controlled.
These include Go probes, Node.js SIGUSR1 signal injection, and Java agent attachment.

Unlike protocol instrumentation, runtimes are not about capturing specific telemetry signals—they are about *how* to instrument a service once it's selected.
Each runtime has a simple structure: `enabled` (boolean) controls whether to attempt injection, and `filter` provides optional per-runtime refinement for which selected services receive the injection.
Java also includes additional runtime-specific configuration such as debug controls and attachment timeout.

#### `correlation` Section

The `extensions.obi.correlation` section defines trace-context correlation features that propagate OBI-generated trace context into external streams.
Unlike telemetry instrumentation (protocol signals), correlation features operate *after* traces are captured to enrich related observability data.

For example, `log_trace_annotation` allows trace context to be injected into application logs from selected services, linking logs to traces through context correlation.

#### `network` Section

The `extensions.obi.network` section defines how network observability is configured, including endpoint identity, selection criteria, flow lifecycle controls, interface discovery behavior, enrichment options, and diagnostics. This section is the primary user control for defining how OBI captures and processes network telemetry.

#### `enrich` Section

The `extensions.obi.enrich` section defines enrichment behavior for telemetry, including service naming policy, and general attribute enrichment rules. This section allows users to configure how OBI adds contextual information to telemetry based on various sources.

#### `operations` Section

The `extensions.obi.operations` section defines runtime and operational controls for OBI, including limits, telemetry tuning, capture behavior, logging configuration, profiling options, shutdown behavior, safety controls, and internal metrics configuration. This section is the primary user control for defining how OBI operates in production environments.

### Compatibility and mapping from v1

v2 is a structural redesign of v1, with deterministic compatibility mapping.
Use the table below to find any v1 field and its v2 canonical location.

Important mapping notes:

- OTel pipeline structure ownership moved to top-level declarative sections:
  - `otel_metrics_export` pipeline structure and transport settings → `meter_provider.*`
  - `prometheus_export.path` → `meter_provider.*`
  - `otel_traces_export` pipeline structure and transport/sampler settings → `tracer_provider.*`
- OBI runtime telemetry tuning is mapped under `extensions.obi.operations.telemetry`:
  - Common metric tuning stays under `extensions.obi.operations.telemetry.metrics`.
  - Prometheus-specific metric tuning is grouped under `extensions.obi.operations.telemetry.metrics.prometheus`.
  - Trace reporter cache tuning is under `extensions.obi.operations.telemetry.traces`.
- Some mappings are non-1:1:
  - `filter.application` fans out to protocol+signal filters.
  - `filter.network` fans out to network signal filters.
  - `metrics.features` maps to protocol metric enablement and network capture enablement.
  - `discovery.skip_go_specific_tracers` maps to `runtimes.go.enabled` with inverted semantics.

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
| `discovery.skip_go_specific_tracers` | `extensions.obi.runtimes.go.enabled` | Inverted boolean mapping |
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
| `ebpf.log_enricher.cache_size` | `extensions.obi.correlation.log_trace_annotation.cache.size` | Move + rename |
| `ebpf.log_enricher.cache_ttl` | `extensions.obi.correlation.log_trace_annotation.cache.ttl` | Move + rename |
| `ebpf.log_enricher.async_writer_workers` | `extensions.obi.correlation.log_trace_annotation.async_writer.workers` | Move + rename |
| `ebpf.log_enricher.async_writer_channel_len` | `extensions.obi.correlation.log_trace_annotation.async_writer.channel_len` | Move + rename |
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
| `javaagent.attach_timeout` | `extensions.obi.runtimes.java.attach_timeout` | Move |
| `javaagent.debug` | `extensions.obi.runtimes.java.debug.enabled` | Move + rename |
| `javaagent.debug_instrumentation` | `extensions.obi.runtimes.java.debug.bytecode_instrumentation` | Move + rename |
| `javaagent.enabled` | `extensions.obi.runtimes.java.enabled` | Simplified to boolean |
| `log_config` | `extensions.obi.operations.logging.format` | Move + rename |
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
| `nodejs.enabled` | `extensions.obi.runtimes.nodejs.enabled` | Simplified to boolean |
| `otel_metrics_export.histogram_aggregation` | `meter_provider.readers[0].periodic.exporter.otlp_grpc.default_histogram_aggregation` | OTel ownership move + declarative reader/exporter shape |
| `otel_metrics_export.reporters_cache_len` | `extensions.obi.operations.telemetry.metrics.reporters_cache_len` | Move to OBI-owned telemetry tuning |
| `otel_metrics_export.ttl` | `extensions.obi.operations.telemetry.metrics.ttl` | Move to OBI-owned telemetry tuning |
| `otel_metrics_export.extra_span_resource_attributes` | `extensions.obi.operations.telemetry.metrics.prometheus.extra_span_resource_attributes` | Move to OBI-owned telemetry tuning |
| `otel_traces_export.batch_timeout` | `tracer_provider.processors[0].batch.schedule_delay` | OTel ownership move + rename + duration(ms) representation |
| `otel_traces_export.max_queue_size` | `tracer_provider.processors[0].batch.max_queue_size` | OTel ownership move + declarative processor list shape |
| `otel_traces_export.reporters_cache_len` | `extensions.obi.operations.telemetry.traces.reporters_cache_len` | Move to OBI-owned telemetry tuning |
| `otel_traces_export.sampler.arg` | `tracer_provider.sampler` | OTel ownership move + semantic translation (no 1:1 arg field in declarative schema) |
| `otel_traces_export.sampler.name` | `tracer_provider.sampler` | OTel ownership move + semantic translation (no 1:1 name field in declarative schema) |
| `profile_port` | `extensions.obi.operations.profiling.port` | Move |
| `prometheus_export.allow_service_graph_self_references` | `extensions.obi.operations.telemetry.metrics.prometheus.allow_service_graph_self_references` | Move to OBI-owned telemetry tuning |
| `prometheus_export.extra_resource_attributes` | `extensions.obi.operations.telemetry.metrics.prometheus.extra_resource_attributes` | Move to OBI-owned telemetry tuning |
| `prometheus_export.extra_span_resource_attributes` | `extensions.obi.operations.telemetry.metrics.prometheus.extra_span_resource_attributes` | Move to OBI-owned telemetry tuning |
| `prometheus_export.port` | `meter_provider.readers[1].pull.exporter.prometheus/development.port` | OTel ownership move + declarative reader/exporter shape |
| `prometheus_export.path` | _No canonical OTel core path in current declarative schema_ | Distribution-specific/unsupported in current target shape |
| `prometheus_export.service_cache_size` | `extensions.obi.operations.telemetry.metrics.prometheus.span_metrics_service_cache_size` | Move to OBI-owned telemetry tuning + rename |
| `routes.max_path_segment_cardinality` | `extensions.obi.instrumentation.http.routes.max_path_segment_cardinality` | Move |
| `routes.unmatched` | `extensions.obi.instrumentation.http.routes.unmatched` | Move |
| `routes.wildcard_char` | `extensions.obi.instrumentation.http.routes.wildcard_char` | Move |
| `shutdown_timeout` | `extensions.obi.operations.shutdown.timeout` | Move |
| `trace_printer` | `extensions.obi.operations.logging.debug_trace_output` | Move + rename |

## Related docs

- Migration, validation, and tooling plan: [migration.md](migration.md)
- OBI extension schema artifact: [obi-extension.schema.json](obi-extension.schema.json)

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
