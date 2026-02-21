# OBI Configuration Composition Draft

Status: Draft for discussion  
Audience: OBI maintainers and contributors  
Scope: configuration model, schema, validation, and migration UX

## Related docs

- Principles and rename governance: `devdocs/config/principles.md`
- Full target-shape default example (mapped from current defaults): `devdocs/config/default-configuration-example.yaml`
- User-centric design drivers (top 10 use cases): `devdocs/config/user-use-cases.md`

## User-centric redesign anchor

The next schema iteration SHOULD be derived from `devdocs/config/user-use-cases.md` first, then validated against implementation constraints.

## V2 design goals (journey-first)

- Users SHOULD configure each concern in one place.
- Protocol/instrumentation-specific settings (for example HTTP) MUST be configured under one protocol section.
- Users SHOULD be able to complete common journeys by editing only one primary section.
- Canonical runtime/effective config MAY be expanded internally, but authored config MUST stay task-centric.

## Target Schema Shape (Authored v2)

### High-level shape

```yaml
version: "2.0"

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

### One concern, one place rules

- HTTP instrumentation configuration MUST live under `extensions.obi.instrumentation.http`.
  - This includes enablement, payload extraction, protocol parsing knobs, and HTTP-specific enrichment behavior.
- Trace sampler configuration MUST live under top-level `tracer_provider.sampler` (OTel sampler `name`/`arg`).
- Every protocol under `extensions.obi.instrumentation.<protocol>` MUST scope enablement by signal using
  - `enabled.traces` and
  - `enabled.metrics`.
- Every protocol under `extensions.obi.instrumentation.<protocol>` MUST scope filters by signal using
  - `filters.traces` and
  - `filters.metrics`.
- Filter semantics are allow-list style: records that match all configured criteria are forwarded; non-matching records are dropped.
- Within each filter rule, `match` keeps matching values and `not_match` keeps values that do not match.
- SQL driver-specific controls MUST live under `extensions.obi.instrumentation.sql.mysql` and `extensions.obi.instrumentation.sql.postgres`.
- Go-specific tracer strategy MUST live under `extensions.obi.instrumentation.go` (for example `enabled`).
- Protocol buffer and parser knobs MUST live under the corresponding protocol section (for example HTTP/Kafka/SQL), not under a generic runtime bag.
- When multiple fields share a semantic prefix (for example `cache_*`, `async_writer_*`, `backoff_*`, `debug_*`), authored v2 config SHOULD group them into nested objects rather than repeating prefixes.
- Capture runtime/debug/performance toggles (for example `pid_filter.disabled`) MUST live under `extensions.obi.operations.capture`.
- Network observability controls MUST live under `extensions.obi.network.capture`, grouped by user intent:
  - `endpoint_identity` for host/agent address identity,
  - `selection` for interface/protocol/cidr scoping,
  - `filters` for network-flow filtering policy (signal-scoped `traces` and `metrics` sections),
  - `flow_lifecycle` for flow cache, dedupe, and sampling,
  - `interface_discovery` for watch vs poll behavior,
  - `enrichment` for GeoIP and reverse DNS,
  - `diagnostics` for operator-facing flow debug output.
- Service selection MUST live under `extensions.obi.selection` only.
  - `extensions.obi.selection` MUST use a single ordered `rules` list (not separate include/exclude lists).
  - Selection behavior knobs (polling and ordering defaults) MUST live under `extensions.obi.selection.policy`.
  - Every rule in `extensions.obi.selection.rules[]` SHOULD define:
    - `name`: a stable, kebab-case identifier (for example `exclude-otlp-exporters`).
    - `description`: a short operator-facing explanation of intent/effect.
  - Already-instrumented target exclusion MUST be encoded as an `action: exclude` rule with OTLP export detection parameters under `extensions.obi.selection.rules[].match.process.exports_otlp`.
  - Executable path exclusions (for Linux system paths) MUST be encoded as `extensions.obi.selection.rules[].match.process.exe_path_glob`.
  - Kubernetes namespace exclusions MUST be encoded as `extensions.obi.selection.rules[].match.kubernetes.namespace_glob`.
- Route harvesting controls (timeouts, disabled languages, language-specific delays) MUST live under `extensions.obi.instrumentation.http.routes.discovery`.
- Enricher runtime configuration SHOULD live under `extensions.obi.enrich.enrichers.*` (for example Kubernetes informer/auth/cache controls).
- Service identity enrichment policy SHOULD live under `extensions.obi.enrich.service_name`.
  - `extensions.obi.enrich.service_name.rules[]` SHOULD define `id`, `from`, and `map` entries.
  - `extensions.obi.enrich.service_name.rules[]` order SHOULD define precedence (earlier rules win for conflicting target fields).
- Attribute enrichment policy SHOULD live under `extensions.obi.enrich.attributes.rules[]`.
  - `extensions.obi.enrich.attributes.rules[]` SHOULD define `id`, `from`, and `add.map` entries.
  - `add.map` SHOULD declare target attribute keys with ordered source lists.
  - `extensions.obi.enrich.attributes.rules[]` order SHOULD define precedence (earlier rules win for conflicting target attributes).
- Signal and cost controls MUST live under `extensions.obi.optimize` only.
- Export and pipeline definition MUST live in top-level OTel declarative sections (`tracer_provider`, `meter_provider`, `resource`, `propagator`).
- Runtime/operational controls MUST live under `extensions.obi.operations` only.

### Ownership model

- Authored user-facing config is `extensions.obi.*` and is optimized for user journeys.
- Effective/canonical runtime config MAY expand into lower-level internal structures after validation.
- Legacy OBI keys are migration inputs only; they are not canonical in v2 authored config.

### Journey to primary section mapping

| User journey | Primary authored section |
|---|---|
| Instrument all services on platform `<X>` | `extensions.obi.selection` |
| Scope to only `<Y>` services | `extensions.obi.selection` |
| Enable network observability | `extensions.obi.network` |
| Configure HTTP instrumentation | `extensions.obi.instrumentation.http` |
| Configure language-specific behavior (Java/Node.js) | `extensions.obi.instrumentation.java` / `extensions.obi.instrumentation.nodejs` |
| Add Kubernetes metadata enrichment | `extensions.obi.enrich.enrichers.kubernetes` |
| Reduce cost and telemetry volume | `extensions.obi.optimize` |
| Send telemetry to OTLP/Prometheus | top-level `tracer_provider` / `meter_provider` |
| Leverage Collector receiver pipelines | Collector pipeline sections + top-level declarative config |
| Operate safely in production | `extensions.obi.operations` |
| Validate config before rollout | `obi config validate` (CLI/utility) |
| Migrate from legacy config | `obi config migrate` (CLI/utility) |

## Grounded Analysis: What OBI Supports Today and How It Maps

This inventory is grounded in current config structs and tags from:

- `pkg/obi/config.go`
- `pkg/obi/network_cfg.go`
- `pkg/config/ebpf_tracer.go`
- `pkg/config/payload_extraction.go`
- `pkg/config/log_enricher.go`
- `pkg/appolly/services/criteria.go`
- `pkg/export/otel/otelcfg/config_metrics.go`
- `pkg/export/otel/otelcfg/config_traces.go`
- `pkg/export/prom/prom.go`

### Current capability families and mapping

| Capability family | Existing config surface (today) | Target config surface |
|---|---|---|
| eBPF tracer behavior | `ebpf.*` | `extensions.obi.operations.capture.*`, `extensions.obi.instrumentation.*`, and `extensions.obi.network.capture.*` |
| App discovery and target selection | `discovery.*`, `open_port`, `target_pids`, `AutoTargetExe`, `AutoTargetLanguage`, `executable_path` | `extensions.obi.selection.policy.*` + `extensions.obi.selection.rules[]` (except route-discovery controls) |
| Route naming harvest behavior | `discovery.route_harvester_timeout`, `discovery.disabled_route_harvesters`, `discovery.route_harvester_advanced.*` | `extensions.obi.instrumentation.http.routes.discovery.{timeout,disabled_languages,java.delay}` |
| Network observability capture | `network.*` | `extensions.obi.network.capture.*` |
| Kubernetes metadata decoration | `attributes.kubernetes.*` | `extensions.obi.enrich.enrichers.kubernetes.*` (metadata runtime) + `extensions.obi.enrich.service_name.rules[]` (identity mapping policy) |
| Attribute decoration/selection | `attributes.*` | `extensions.obi.enrich.attributes.rules[]` |
| Route normalization | `routes.*` | `extensions.obi.instrumentation.http.routes.*` |
| Name resolution | `name_resolver.*` | `extensions.obi.enrich.service_name.{cache,rules}` |
| Language toggles/attach controls | `nodejs.*`, `javaagent.*`, `discovery.skip_go_specific_tracers` | `extensions.obi.instrumentation.nodejs.*`, `extensions.obi.instrumentation.java.*`, `extensions.obi.instrumentation.go.*` |
| Payload extraction | `ebpf.payload_extraction.*` | `extensions.obi.instrumentation.http.payload_extraction.*` |
| Log enrichment | `ebpf.log_enricher.*` | `extensions.obi.instrumentation.http.log_enrichment.*` |
| OBI-local filtering/selection | `filter.application`, `filter.network`, `metrics.features` | `extensions.obi.instrumentation.<protocol>.filters.<signal>`, `extensions.obi.network.capture.filters.<signal>`, and `extensions.obi.instrumentation.<protocol>.enabled.<signal>` |
| Runtime operations | `log_level`, `log_config`, `shutdown_timeout`, `enforce_sys_caps`, `profile_port`, `channel_*`, `internal_metrics.*` | `extensions.obi.operations.*` |
| OTLP metrics/traces export config | `otel_metrics_export.*`, `otel_traces_export.*` | top-level `meter_provider.*`, `tracer_provider.*` |
| Prometheus export config | `prometheus_export.*` | top-level `meter_provider.*` |
| Receiver integration behavior | receiver runtime wiring | collector pipeline sections + capability validation |

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

## Explicit Key-by-Key Migration Matrix

### Core OBI controls

| Current key | Current location | Target canonical location | Rule |
|---|---|---|---|
| `ebpf` | top-level | `extensions.obi.instrumentation.*` / `extensions.obi.network.capture.*` | Move + split |
| `network` | top-level | `extensions.obi.network.capture.{endpoint_identity,selection,flow_lifecycle,interface_discovery,enrichment,diagnostics}` | Move + group |
| `filter.application` | top-level | `extensions.obi.instrumentation.<protocol>.filters.{traces,metrics}` | Move + fan-out |
| `filter.network` | top-level | `extensions.obi.network.capture.filters.{traces,metrics}` | Move + fan-out |
| `attributes` | top-level | `extensions.obi.enrich.attributes` / `extensions.obi.enrich.enrichers.kubernetes` / `extensions.obi.enrich.service_name.rules` | Move + split |
| `routes` | top-level | `extensions.obi.instrumentation.http.routes` | Move |
| `name_resolver` | top-level | `extensions.obi.enrich.service_name` | Move + rename |
| `discovery` | top-level | `extensions.obi.selection` | Move |
| `javaagent` | top-level | `extensions.obi.instrumentation.java` | Move |
| `nodejs` | top-level | `extensions.obi.instrumentation.nodejs` | Move |
| `internal_metrics` | top-level | `extensions.obi.operations.internal_metrics` | Move |
| `optimize.sampling.network_packets` | top-level optimize | `extensions.obi.operations.limits.network_packets` | Move + flatten |
| `optimize.cardinality.metric_span_names_limit` | top-level optimize | `extensions.obi.operations.limits.metric_span_names` | Move + flatten + rename |
| `log_level` | top-level | `extensions.obi.operations.logging.level` | Move |
| `log_config` | top-level | `extensions.obi.operations.logging.startup_dump` | Move + rename |
| `profile_port` | top-level | `extensions.obi.operations.profiling.port` | Move |
| `shutdown_timeout` | top-level | `extensions.obi.operations.shutdown.timeout` | Move |
| `enforce_sys_caps` | top-level | `extensions.obi.operations.safety.enforce_system_capabilities` | Move + rename |

### Legacy export keys (de-canonicalize)

| Current key | Current location | Target canonical location | Standalone | Receiver | Rule |
|---|---|---|---:|---:|---|
| `otel_metrics_export` | top-level | top-level declarative `meter_provider.*` | I | F | Rewrite where deterministic; else fail |
| `otel_traces_export` | top-level | top-level declarative `tracer_provider.*` | I | F | Rewrite where deterministic; else fail |
| `otel_traces_export.sampler` | top-level | top-level declarative `tracer_provider.sampler` | I | F | Rewrite where deterministic |
| `prometheus_export` | top-level | top-level declarative `meter_provider.*` | I | F | Rewrite where deterministic; else fail |
| `trace_printer` | top-level | `extensions.obi.operations.logging.debug_trace_output` | I | F | Rewrite where deterministic; else fail |
| `metrics.features` | top-level | `extensions.obi.instrumentation.<protocol>.enabled.metrics` and `extensions.obi.network.capture.enabled` | A | A | Move signal enablement to owning protocol/network sections |

### Target selection and discovery aliases

| Current key | Current location | Target canonical location | Rule |
|---|---|---|---|
| `executable_path` (deprecated) | top-level | `extensions.obi.selection.rules[].match.process.exe_path_regex` | Keep alias + warn |
| `AutoTargetExe` | top-level/env alias | `extensions.obi.selection.rules[].match.process.exe_path_glob` | Canonicalize |
| `open_port` | top-level | `extensions.obi.selection.rules[].match.network.open_ports` | Move |
| `AutoTargetLanguage` | top-level | `extensions.obi.selection.rules[].match.language.languages` | Move |
| `target_pids` | top-level | `extensions.obi.selection.rules[].match.process.pids` | Move |
| `discovery.exclude_otel_instrumented_services` | discovery | `extensions.obi.selection.rules[].match.process.exports_otlp` (`action: exclude`) | Rewrite |
| `discovery.default_otlp_grpc_port` | discovery | `extensions.obi.selection.rules[].match.process.exports_otlp.port` | Rewrite |
| `discovery.bpf_pid_filter_off` | discovery | `extensions.obi.operations.capture.pid_filter.disabled` | Move |
| `discovery.skip_go_specific_tracers` | discovery | `extensions.obi.instrumentation.go.enabled` (inverted boolean) | Rewrite |
| `javaagent.debug_instrumentation` | javaagent | `extensions.obi.instrumentation.java.debug.bytecode_instrumentation` | Rename + move |
| `discovery.services` (deprecated) | discovery | `extensions.obi.selection.rules` with `action: include` | Rewrite + warn |
| `discovery.exclude_services` (deprecated) | discovery | `extensions.obi.selection.rules` with `action: exclude` | Rewrite + warn |
| `discovery.default_exclude_services` (deprecated) | discovery | `extensions.obi.selection.rules` with `action: exclude` (default marker) | Rewrite + warn |
| `discovery.excluded_linux_system_paths` | discovery | `extensions.obi.selection.rules[].match.process.exe_path_glob` (`action: exclude`) | Rewrite paths with `/*` suffix |

### Rename policy and rationale map

Rename reason codes:

- **OTEL**: aligns term/location with OTel declarative model.
- **OWN**: places key under canonical owning section.
- **CONS**: improves naming consistency and syntax consistency with the surrounding model.
- **TERM**: improves terminology clarity while preserving semantics.
- **DEBT**: resolves historical/deprecated naming debt.

| Rename | Reason code(s) | Rationale |
|---|---|---|
| `name_resolver` → `enrich.service_name` | OWN, CONS | Places service identity resolution controls under a dedicated service-name enrichment section in v2 authored config. |
| `log_config` → `operations.logging.startup_dump` | OWN, TERM | Clarifies this controls startup config logging format/output intent, not global logger behavior. |
| `enforce_sys_caps` → `operations.safety.enforce_system_capabilities` | TERM, OWN, CONS | Expands abbreviation and places under safety policy where enforcement semantics belong; aligns with long-form operation keys. |
| `executable_path` (legacy) → `selection.rules[].match.process.exe_path_regex` | TERM, DEBT, CONS | Makes selector type explicit and places it in user-facing selection controls. |
| `AutoTargetExe` → `selection.rules[].match.process.exe_path_glob` | TERM, DEBT, CONS | Removes mixed casing/legacy naming and makes match type explicit (`glob`) in consistent selection syntax. |
| `open_port` → `selection.rules[].match.network.open_ports` | TERM, OWN, CONS | Reflects `IntEnum` semantics (single values and ranges), grouped in selection controls. |
| `AutoTargetLanguage` → `selection.rules[].match.language.languages` | TERM, DEBT, CONS | Removes legacy “AutoTarget” phrasing; keeps pure selector meaning in selection syntax. |
| `javaagent.debug_instrumentation` → `instrumentation.java.debug.bytecode_instrumentation` | TERM, CONS | Makes scope explicit (bytecode instrumentation debug) and distinguishes it from general Java agent debug output. |
| `discovery.services` → `discovery.instrument` | DEBT, TERM | Aligns to current discovery terminology and removes deprecated regex-era naming. |
| `discovery.exclude_services` → `discovery.exclude_instrument` | DEBT, TERM | Mirrors canonical include/exclude vocabulary for instrumentation selection. |
| `discovery.default_exclude_services` → `discovery.default_exclude_instrument` | DEBT, TERM | Same as above, for default exclusion path. |

Policy application notes:

- Moves that only change nesting without changing key term are treated as ownership moves, not renames.
- Every rename in migration tooling output SHOULD include its reason code(s).
- Consistency checks SHOULD be part of schema review, including casing style, pluralization rules, selector suffix patterns (`*_glob`, `*_regex`), and hierarchy term reuse.

### Recent v2 rename log

This short log tracks recent user-facing naming decisions already reflected in `default-configuration-example.yaml`.

| Legacy/current key | v2 authored key | Type | Notes |
|---|---|---|---|
| `discovery.skip_go_specific_tracers` | `extensions.obi.instrumentation.go.enabled` (inverted boolean) | Rename + move | `enabled: true` means Go package-level instrumentation is on; legacy key was a negative switch. |
| `javaagent.debug_instrumentation` | `extensions.obi.instrumentation.java.debug.bytecode_instrumentation` | Rename + move | Clarifies this is ByteBuddy/bytecode instrumentation debug, not general Java agent debug. |
| `discovery.default_otlp_grpc_port` | `extensions.obi.selection.rules[].match.process.exports_otlp.port` | Move + reshape | OTLP export-detection fallback port now lives with already-instrumented exclusion rule semantics. |
| `discovery.bpf_pid_filter_off` | `extensions.obi.operations.capture.pid_filter.disabled` | Move | Capture runtime debug/filter toggle is now grouped under operations capture controls. |

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
