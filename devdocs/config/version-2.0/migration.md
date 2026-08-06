# Migrate OBI configuration from v1 to v2

This guide explains how to move an existing OBI configuration to Config v2
with a workflow designed to preserve effective behavior. It covers the
standalone OBI binary and the OBI Collector receiver.

> [!IMPORTANT]
> Use Config v2 for standalone OBI only with a release whose notes explicitly
> say that standalone Config v2 loading is enabled. Config v2 in OBI v0.10.0
> is internal groundwork, not a public runtime configuration interface. The
> complete public release is tracked by the
> [Config v2 release gate](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2251),
> including
> [standalone loading](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2535)
> and its
> [implementation PR](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/2682).
> A successful `obi config validate` checks the document; it does not prove
> that the installed OBI runtime can load v2.

The migration command is designed to preserve effective behavior. It combines
a v2 round-trip comparison with checks for structural mappings that cannot be
compared field-for-field, and rejects detected values that cannot be
preserved. Static checks cannot cover external environment overlays or runtime
dependencies, so the canary comparison in this guide remains required.

## Before you migrate

1. Keep the old OBI binary or container image, its exact version or digest,
   and an unchanged copy of the v1 file.
2. Inventory configuration supplied outside the file: environment variables,
   command-line arguments, Kubernetes manifests, Helm values, and injected
   secrets.
3. Obtain an OBI binary from the release that will run v2. Do not replace the
   running binary yet.
4. Confirm that the release notes say both standalone loading and the
   migration CLI are supported.
5. Choose one representative instance for a canary. Keep the rest on v1 until
   telemetry from the canary has been compared.

The command migrates one YAML file. Runtime environment overrides such as
`OTEL_EBPF_*`, `OTEL_EXPORTER_OTLP_*`, and `OTEL_SERVICE_NAME` are not read as
additional v1 configuration. Merely carrying a legacy variable into the v2
deployment does not preserve its override. Materialize its reviewed value or
reference that variable explicitly from the canonical v2 field, as shown in
[Rewire v1 environment overrides](#rewire-v1-environment-overrides).

Do not put credentials into a temporary migration file merely to make them
visible to the command. Keep secret-backed values external, but wire their
variables explicitly into the supported v2 field that consumes them.

Substitution happens before output is written. A secret referenced inside the
source file can therefore be materialized into the generated file. Keep the
migration directory private and inspect its handling as secret material.

## Run the migration

The exact command shape is:

```text
obi config migrate [--mode=standalone|receiver] <path>
```

It accepts one file path. Standalone is the default; use `--mode=receiver` for
a legacy `receivers.obi` component body. It does not accept standard input, an
output option, or source and target version flags.

Migration uses the v1 runtime configuration type and the same internal
v1-to-v2 converter as OBI. It rejects malformed input, unknown v1 fields, and
values that cannot survive a v2 round trip, then validates the generated
document before writing it.

Create new files in a private temporary directory so neither the source file
nor an earlier result can be overwritten accidentally:

```shell
umask 077
migration_dir="$(mktemp -d)"

obi config migrate ./obi-v1.yaml \
  > "${migration_dir}/obi-v2.yaml" \
  2> "${migration_dir}/migration-report.txt"
```

On success, standard output is either a complete standalone v2 document or,
with `--mode=receiver`, a complete v2 receiver component body. Standard error
is a deterministic summary report. The report starts with:

```text
migrated v1 config to OBI config v2
```

It may then list broad non-1:1 transformation categories present in the source:
filter fan-out, discovery-rule reshaping, inverted Go tracer enablement,
directional route expansion, and exporter ownership changes. It is not a
field-by-field mapping report. Save both streams and review the generated YAML.
The CLI has no separate warning class: report bullets are informational, while
unsupported values make the command fail.

Migration, parsing, and validation failures detected before output writing
leave standard output empty, and standard error starts with `migration failed:`.
An output write failure such as a full filesystem can leave a partial target
file; accept the file only when the command exits `0`. Unsupported or lossy
values are reported with relevant v1 paths, for example:

```text
migration failed: fields are outside the supported v1-to-v2 migration contract: prometheus_export.path
```

Given the same file and substitution environment, repeated runs produce the
same YAML and report. Confirm that before editing the result:

```shell
obi config migrate ./obi-v1.yaml \
  > "${migration_dir}/obi-v2-second.yaml" \
  2> "${migration_dir}/migration-report-second.txt"

diff -u "${migration_dir}/obi-v2.yaml" \
  "${migration_dir}/obi-v2-second.yaml"
diff -u "${migration_dir}/migration-report.txt" \
  "${migration_dir}/migration-report-second.txt"
```

## Follow the tested example

The checked-in
[v1 migration input](examples/migration-v1.yaml) includes a discovery selector,
an application filter, global HTTP route settings, OTLP traces and metrics,
and environment substitution. Its
[generated standalone v2 result](examples/migration-v2.yaml) is the unedited
output of the real migration command.

Reproduce it with:

```shell
CART_ROOT=/srv OTLP_HOST=collector \
  obi config migrate \
  ./devdocs/config/version-2.0/examples/migration-v1.yaml \
  > ./migration-v2.yaml \
  2> ./migration-report.txt

diff -u \
  ./devdocs/config/version-2.0/examples/migration-v2.yaml \
  ./migration-v2.yaml

obi config validate ./migration-v2.yaml
```

The generated file is intentionally verbose. It materializes the v1 values and
defaults represented by the current v2 model. Unmodelled runtime behavior can
still vary by release, which is why the target version must be pinned and
canary-tested. Do not remove apparently redundant `false`, zero, empty, or
default-valued fields before that test. Presence and omission are not
interchangeable for every v2 field.

The most visible rewrites in this example are:

| v1 | v2 |
|---|---|
| `discovery.instrument` | Ordered `extensions.obi.capture.rules` |
| `filter.application` | Every protocol's trace and metric filters |
| Flat global `routes` | HTTP `routes.incoming` and `routes.outgoing` |
| `otel_traces_export` | Top-level `tracer_provider` |
| `otel_metrics_export` | Top-level `meter_provider` |
| `log_level` | Top-level standard `log_level` |

## Review behavior changes

The migration output is intended to preserve the represented effective v1
configuration, but native v2 authoring has different defaults and structure.
Review these points before deployment.

### Capture policy and ordered rules

Config v2 uses a default-on policy: omitting
`capture.policy.default_action`, or setting it to `include`, captures processes
that no rule excludes. This differs from a v1 file with no target selector,
where application capture is disabled.

The migrator writes `default_action: exclude` when needed to preserve v1
selection. It emits `first_match_wins` with exclusion rules before inclusion
rules. The target adapter in
[#2682](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/2682)
also accepts `last_match_wins`; preserving runtime exclusion precedence
requires includes before excludes in that mode. The migrator does not emit
that alternative. It also resolves the precedence between
deprecated regex selectors, current glob selectors, and the top-level
`executable_path`, `open_port`, and `target_pids` fallbacks. The output is the
effective ordered policy, not a syntactic copy of every selector.

Do not reorder generated rules without retesting:

- any matching exclusion takes precedence over inclusion;
- with generated `first_match_wins`, the first matching YAML include rule's
  refinement wins;
- generated include rules reverse the effective v1 selector order because v1
  applies the later matching selector's refinement;
- when multiple v1 include selectors are effective, `exports` must be present
  on every selector or absent from every selector, and the same rule applies
  independently to `routes`; the command rejects mixed explicit and inherited
  refinements because a single winning v2 rule cannot preserve v1's
  field-by-field layering safely;
- explicitly setting `rules: []` removes the generated built-in workload
  exclusions;
- an empty rule list with `default_action: include` is default-on;
- an empty rule list with `default_action: exclude` captures nothing.

### Protocol and signal filters

The v1 `filter.application` value is global. Migration copies it to trace and
metric filters for every application protocol. It similarly copies
`filter.network` and `filter.stats` into their supported signal locations.

Keep every migrated application protocol's trace and metric maps identical to
`capture.instrumentation.http.filters.traces`. Keep each network flow trace
and metric map identical, and do the same for network stats. The target loader
rejects any difference because each family still has one runtime filter.
Protocol- and signal-specific narrowing is modeled in the v2 document but is
not yet a supported runtime behavior. Its final semantics remain tracked in
[#1282](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1282).
Do not invent different SQL, HTTP, trace, or metric filters during migration.

### HTTP routes

Each v1 global route field is copied to both
`capture.instrumentation.http.routes.incoming` and `.outgoing`:

- `unmatched`
- `patterns`
- `ignored_patterns`
- `ignore_mode`
- `wildcard_char`
- `max_path_segment_cardinality`

Per-service v1 incoming and outgoing routes retain their direction under the
matching capture rule when global `routes.patterns` is empty. When a v1 file
combines non-empty global patterns with a non-empty per-service direction,
migration rejects that selector route path. V1 tries global patterns first and
then service patterns, while a v2 refinement replaces the inherited array;
neither direct replacement nor concatenation preserves matcher precedence.

In native v2, an omitted per-service route field inherits the global value. An
explicit array replaces the inherited array, and `[]` clears it.

### Exporters and OpenTelemetry ownership

Standalone v2 uses top-level OpenTelemetry declarative providers:

- trace batching, sampling, and OTLP export are under `tracer_provider`;
- metric intervals and OTLP or Prometheus readers are under `meter_provider`;
- `resource` owns the supported host resource attributes;
- top-level `log_level` owns OBI log verbosity.

The migrator in the current CLI baseline emits only one batch OTLP/gRPC span
exporter, one periodic OTLP/gRPC metric exporter, and one Prometheus
development pull reader. Do not add other declarative SDK settings only
because the upstream schema accepts them. Some schema-modeled provider fields
are not yet applied by the OBI runtime.

V1 infers an omitted OTLP protocol from the endpoint. An endpoint using port
4318, or another endpoint that does not imply gRPC, is effectively
HTTP/protobuf. The current migration command rejects its `endpoint` path
because its round-trip target still emits only gRPC. Add `protocol: grpc` only
when the actual collector endpoint already speaks gRPC. This explicit setting
also allows a non-standard gRPC port to migrate.

HTTP export does have a manual declarative representation in a release that
includes the gated
[standalone HTTP importer](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/2682).
Use `encoding: protobuf` for v1 `http/protobuf` or an inferred HTTP endpoint,
and `encoding: json` for v1 `http/json`:

```yaml
tracer_provider:
  processors:
    - batch:
        exporter:
          otlp_http:
            endpoint: http://collector:4318
            encoding: protobuf
meter_provider:
  readers:
    - periodic:
        exporter:
          otlp_http:
            endpoint: http://collector:4318
            encoding: protobuf
```

These are provider fragments, not a complete configuration. Preserve an
explicit v1 signal endpoint exactly, including any path. A v1 common
`OTEL_EXPORTER_OTLP_ENDPOINT` appends `/v1/traces` and `/v1/metrics`; when
rewiring that environment overlay, use those signal-specific URLs in the two
v2 exporters. Validate the edited complete document with the target release.
If its release notes do not include HTTP importer support, remain on v1 rather
than adding a provider shape that its runtime cannot apply.

The target importer in #2682 accepts declarative `headers` and `headers_list`
on supported OTLP/gRPC and OTLP/HTTP exporters. The migration command cannot
inspect runtime header variables and does not copy them into YAML. Keep
`OTEL_EXPORTER_OTLP_HEADERS`,
`OTEL_EXPORTER_OTLP_TRACES_HEADERS`, and
`OTEL_EXPORTER_OTLP_METRICS_HEADERS` as secret-backed runtime inputs, or map a
reviewed secret provider into the corresponding declarative exporter header.
Signal-specific environment headers override a duplicate common header.
Validate with the target release and verify authentication at the exporter;
static validation does not contact it.

In Collector receiver mode, the Collector's service pipelines, processors,
exporters, exporter headers, resource processing, and telemetry settings own
these concerns. Do not put exporter headers in `receivers.obi`.

### Strict input and full defaults

Migration rejects unknown v1 fields, multiple YAML documents, invalid v1
runtime combinations, already-v2 input, and detected source values outside the
supported migration contract. Validation rejects unknown OBI extension fields
and invalid supported shapes. In the target adapter delivered by #2682,
`attribute_limits` is rejected whenever present; `disabled: true`, non-empty
`distribution`, non-empty `propagator`, `instrumentation/development`, and
`logger_provider` are also rejected. Empty schema placeholders such as
`propagator: {}`, `distribution: {}`, and `disabled: false` do not enable
runtime behavior. Unsupported resource detection, resource schema URLs, and
resource attributes are rejected rather than ignored. A recognized broken v2
document is never retried as v1.

The generated document contains defaults represented by the current v2 model.
There is no promise that a hand-minimized document will have the same behavior,
even when both documents validate.

### Native v2 defaults differ from migrated v1 defaults

The
[authored v2 default-values reference](examples/default-values-reference.fragment.yaml)
is a YAML fragment, not a standalone document and not the result of migrating
an empty or minimal v1 file. The migrator writes different values where parity
requires them:

| Behavior | Native v2 reference | Migrated v1 behavior |
|---|---|---|
| Workload selection | `default_action: include` with built-in workload exclusions | Writes `exclude` when v1 application capture has no effective include selector |
| Explicit `rules: []` | Removes the built-in workload exclusions and captures by the default action | Generated rules materialize applicable v1 selectors and exclusions |
| DNS metrics | Disabled | Enabled when an active v1 metric exporter uses the `*` instrumentation default |

Do not replace generated values with the native reference defaults during an
upgrade.

## Find renamed and restructured fields

The [Config v1 to v2 compatibility table](config-v2.md#compatibility-and-mapping-from-v1)
lists canonical locations for fields supported by the migrator. The major
group moves are:

| v1 group | v2 owner |
|---|---|
| Discovery and top-level selectors | `extensions.obi.capture.policy` and `.rules` |
| Application protocol settings | `extensions.obi.capture.instrumentation` |
| Network flows and network statistics | `extensions.obi.capture.network` |
| eBPF engine, batching, propagation, and buffers | `extensions.obi.capture.engine` and protocol sections |
| Kubernetes and name resolution | `extensions.obi.enrich` |
| Log trace annotation | `extensions.obi.correlation` |
| OBI logging, profiling, shutdown, and internal metrics | `extensions.obi.daemon` |
| Trace and metric exporters | Top-level `tracer_provider` and `meter_provider` |

Supported match criteria from deprecated selectors are removed as v2 keys and
reshaped:

- `executable_path`, `open_port`, and `target_pids` become an include rule;
- `discovery.services` and related regex selectors become regex rules;
- `discovery.instrument` and related glob selectors become glob rules;
- deprecated exporter `features` values are normalized through
  `metrics.features` and then split across protocol and network enablement.

Selector naming, per-selector metric features and samplers, and exclusion-rule
refinements are not part of that reshape; the command rejects them as described
below.

## Handle fields that need manual intervention

The command is the executable authority for a particular file. It reports
detected paths whose effective values cannot be represented. The canary remains
the authority for external overrides and runtime behavior. Settings that
require removal, a supported replacement, or a separate deployment decision
include:

| v1 setting | Migration action |
|---|---|
| `prometheus_export.path` | The supported declarative pull exporter has no path field. Use its supported endpoint or keep v1 until the required shape exists. |
| `service_name`, `service_namespace` | Automatic migration rejects these deprecated OBI-wide overrides. Prefer identity on each instrumented target through `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, or Kubernetes metadata. When the same OBI-wide override is intentionally required, map it manually to string `service.name` and `service.namespace` attributes in the standalone top-level `resource`, then validate with a release containing #2682. In receiver mode, use a Collector resource processor instead. |
| `discovery.excluded_linux_system_paths` | This v1 field skips an early language-detection pass; it does not exclude workloads selected by path or port. The default remains an internal runtime behavior, but v2 has no field for custom values. Migration rejects a non-default or explicitly empty list. Do not translate it into an exclude rule, which would suppress telemetry. |
| `health_check.*` | No v2 daemon health-check section exists. Move the health check to the host/orchestrator or keep v1. |
| `jvm_runtime_metrics.sampling_interval` | No v2 field exists. Keep the default or remain on v1 if the override is required. |
| `attributes.instance_id.dns` | V2 can represent explicit `host.name` and `host.id` overrides, but not this DNS lookup control. |
| `ebpf.stats_wakeup_data_bytes` | No v2 field exists. Keep v1 when non-default stats wakeup behavior is required. |
| Selector `name` or `namespace`, any per-selector `metrics.features` or `sampler`, and refinements on exclusion selectors | The current v2 rules cannot preserve these fields. Express supported identity criteria as rule matches; otherwise keep v1. |
| Selector `exports` containing `logs` | V2 rule export refinements represent traces and metrics only. Remove the log-specific override only after verifying equivalent behavior, or keep v1. |
| Multiple include selectors that mix explicit and omitted `exports`, or mix explicit and omitted `routes` | V1 layers each refinement field across every matching selector, while v2 applies one winning rule and resets its omitted refinements. Refactor the selectors so each effective selector states its intended refinement, then test both overlapping and selector-only matches. If behavior depends on conditional inheritance from another selector, keep v1. The command rejects the mixed shape rather than broadening telemetry or changing routes. |
| Non-empty global `routes.patterns` combined with non-empty selector `routes.incoming` or `.outgoing` | V1 uses global-first additive matching while v2 arrays replace inherited patterns. The command rejects the selector route path; keep v1 or redesign and canary-test the policy. |
| A network feature in `metrics.features` with no active metric exporter and `network.enable` omitted or `false` | V1 leaves network capture disabled, while the current v2 enablement shape would turn it on. Migration rejects the relevant `network.enable` or feature path. Keep v1 or explicitly redesign and canary-test network capture; do not enable it only to make migration pass. |
| `ebpf.log_enricher.services` | Correlation filtering is not supported in v2. Do not broaden annotation silently; keep v1 or redesign the deployment. |
| `attributes.sensitive_query_params` | No v2 field exists. Do not remove a redaction setting without an equivalent privacy review. |
| `discovery.exclude_otel_instrumented_services_span_metrics` | No independent v2 selector exists for this legacy span-metrics exception. |
| `metrics.features` values other than application RED, basic network flow, and the individual network-stat features | Span metrics, service graphs, application host/runtime metrics, inter-zone/network-packet variants, and eBPF metrics are not represented by current v2 enablement. |
| Non-default `otel_traces_export.instrumentations`, `otel_metrics_export.instrumentations`, or `prometheus_export.instrumentations` selections involving protocols not modeled by v2 | The v2 protocol enablement section cannot represent every v1 instrumentation. Keep v1 when the command reports a changed instrumentation list. |
| OTLP HTTP protocol or an implicitly HTTP endpoint | Automatic migration supports the emitted OTLP/gRPC provider subset only. In a release that includes [#2682](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/2682), map it manually to the signal's `otlp_http` exporter and preserve the effective endpoint and encoding as described above; otherwise keep v1. |
| `otel_traces_export.protocol: debug` | The v1 debug exporter has no supported declarative provider mapping. `daemon.logging.debug_trace_output` maps `trace_printer`, which is a different output path. Keep v1 when the debug exporter behavior is required. |
| OTLP retry/backoff, custom TLS verification, or SDK log-level overrides | These controls are outside the supported provider subset. Keep v1 when the command reports them unless the target release documents an equivalent declarative field. |
| Custom metric buckets, exponential histogram tuning, native histogram options, or exemplars | These v1 exporter-specific controls are not all represented by the supported v2 provider subset. |
| `otel_metrics_export.extra_span_resource_attributes` | The current importer does not restore this OTLP span-metric setting. The similarly named Prometheus field is a separate setting. |
| `otel_metrics_export.allow_service_graph_self_references` | This OTLP span-metric setting has no current v2 provider mapping. |
| `prometheus_export.disable_build_info`, `ttl`, custom `buckets`, `exemplar_filter`, or `native_histogram.*` | These Prometheus-specific controls are not represented by the supported declarative pull exporter subset. |
| `internal_metrics.avoided_services.disabled` or `.limit` | Avoided-service controls have no v2 daemon mapping. |
| Global samplers outside the documented always-on, always-off, trace-ID-ratio, and parent-based variants | The current importer supports only that built-in subset. Ratio arguments must parse as numbers; other names and per-workload samplers require v1. |
| Non-standard `log_format`, `log_config`, or log-level values outside the documented severity families | V2 normalizes only `text`/`json`, empty/`yaml`/`json`, and DEBUG/INFO/WARN/ERROR severity families. |
| Unknown or non-string metric feature entries | V1 parsing can collapse these entries silently; migration rejects the containing `features` path. Replace them with a documented feature or remove them after review. |

A field explicitly set to its v1 default may pass because the same effective
default is present after round trip even when no dedicated v2 key exists. Do
not interpret that as support for non-default values.

For a deliberate standalone OBI-wide service identity mapping, use:

```yaml
resource:
  attributes:
    - name: service.name
      value: checkout
    - name: service.namespace
      value: shop
```

This is a standalone top-level fragment. It is not valid inside
`receivers.obi`.

If migration fails:

1. keep the original v1 file unchanged;
2. inspect every reported path in the
   [v1 reference](../CONFIG.md) and the compatibility table;
3. decide whether to use a documented v2 replacement, remove an obsolete
   value, or postpone migration;
4. rerun migration from the original file plus only the reviewed adjustment.

## Environment-variable behavior

Migration and validation perform one substitution pass over the file before
decoding. Supported forms are:

```text
${VAR}
${env:VAR}
${VAR:-fallback}
${env:VAR:-fallback}
$(VAR)
$(env:VAR)
$(VAR:-fallback)
$(env:VAR:-fallback)
```

An unset reference without a fallback becomes an empty string. The fallback
form is used when the variable is unset or empty, and it can be combined with
the `env:` prefix with either delimiter. Prefix a substitution token with an
extra dollar sign when it must remain literal through this pass, for example
`$${LATER}` or `$$(LATER)`.

Migration resolves substitutions embedded in the v1 file and then preserves
escaped literal tokens in its output. It does not apply the broader v1 runtime
environment overlay. This matters because normal v1 loading applies defaults,
then file values, then environment variables.

### Rewire v1 environment overrides

Suppose the v1 file omits `ebpf.wakeup_len` and the deployment supplies:

```shell
OTEL_EBPF_BPF_WAKEUP_LEN=999
```

Setting that variable while migrating does not apply the v1 overlay. The
checked-in example proves the behavior:

```shell
CART_ROOT=/srv OTLP_HOST=collector \
OTEL_EBPF_BPF_WAKEUP_LEN=999 \
  obi config migrate \
  ./devdocs/config/version-2.0/examples/migration-v1.yaml \
  > ./migration-v2.yaml \
  2> ./migration-report.txt

grep 'wakeup_len:' ./migration-v2.yaml
```

The result is the v1 file/default value, not the external override:

```text
                    wakeup_len: 500
```

To retain the deployment-controlled value, edit that canonical v2 field to
reference the variable explicitly:

```yaml
extensions:
  obi:
    capture:
      engine:
        batching:
          wakeup_len: ${OTEL_EBPF_BPF_WAKEUP_LEN:-500}
```

Then validate with the canary environment:

```shell
OTEL_EBPF_BPF_WAKEUP_LEN=999 \
  obi config validate ./migration-v2.yaml
```

Apply the same process to every inventoried v1 overlay: find its mapping in the
compatibility table, put a substitution token at that canonical v2 path, and
validate the resulting document. A variable that is not referenced by the v2
document has no migration effect unless the target release explicitly
documents it as a separate runtime input.

Two v1 target selectors exist only as environment fields. If a deployment has:

```shell
OTEL_EBPF_AUTO_TARGET_EXE='/srv/*'
OTEL_EBPF_AUTO_TARGET_LANGUAGE='{go,java}'
```

materialize their effective values as one include rule:

```yaml
extensions:
  obi:
    capture:
      policy:
        default_action: exclude
        match_order: first_match_wins
      rules:
        - action: include
          match:
            process:
              exe_path_glob: ["/srv/*"]
              language_glob: [go, java]
```

`OTEL_GO_AUTO_TARGET_EXE` is a compatibility alias used only when
`OTEL_EBPF_AUTO_TARGET_EXE` is unset; the newer variable wins when both are
set. Preserve the combined executable-and-language match, and place the rule
at the reviewed precedence among any other generated include rules.

Exporter authentication is the exception to the general overlay rule:
supported OTLP exporters continue to read
`OTEL_EXPORTER_OTLP_HEADERS`,
`OTEL_EXPORTER_OTLP_TRACES_HEADERS`, and
`OTEL_EXPORTER_OTLP_METRICS_HEADERS` directly at runtime. Keep these values
secret-backed rather than materializing them during migration. The migration
command and static validation do not prove that a remote exporter accepts
them.

The generated standalone file can contain resolved secret values if the source
referenced them. Treat it as sensitive. In receiver deployments, the
Collector's configuration provider owns substitution during normal Collector
startup; CLI receiver validation performs only the OBI command's substitution
pass and does not prove every Collector provider expression.

For every runtime override, choose one of these approaches:

- materialize its non-secret value in a reviewed v1 copy before migration;
- map it to the documented v2 field with an explicit substitution token;
- keep it as a separate runtime input only when the target release documents
  that variable independently of the v1 overlay.

Run both migration and validation with the same substitution environment that
the canary will use.

## Validate the standalone document

The exact command shape is:

```text
obi config validate [--mode=standalone|receiver] <path>
```

Standalone is the default:

```shell
obi config validate "${migration_dir}/obi-v2.yaml"
```

Success writes:

```text
configuration is valid
```

Validation performs substitution, strict v2 parsing, conversion through the
runtime adapter, and host-independent static validation. It does not start
OBI, connect to an exporter, attach eBPF programs, inspect kernel support, or
prove that the installed runtime dispatches normal startup to the v2 loader.

The commands use these exit codes:

| Exit | Meaning |
|---|---|
| `0` | Migration or validation succeeded, or help was requested. |
| `1` | Reading, parsing, validation, or supported-contract migration failed. |
| `2` | The command, flag, mode, or argument count was invalid. |

Help and usage text are written to standard error. Automation should check the
exit code instead of parsing success text.

The [default configuration example](examples/default-configuration.yaml) is a
complete standalone document that writes debug traces as text for local
verification. Validate it directly:

```shell
obi config validate ./devdocs/config/version-2.0/examples/default-configuration.yaml
```

Replace the debug output with a production exporter before deployment, and
replace its placeholder process selector with the application you intend to
instrument. Use the
[default-values reference fragment](examples/default-values-reference.fragment.yaml)
only to inspect authored defaults; it is intentionally not a configuration
document and must not be passed to `obi config validate`.

## Migrate a Collector receiver

Migrate the legacy receiver component body directly:

```shell
CART_ROOT=/srv \
  obi config migrate --mode=receiver \
  ./devdocs/config/version-2.0/examples/migration-receiver-v1.yaml \
  > ./migration-receiver-v2.yaml \
  2> ./migration-receiver-report.txt

diff -u \
  ./devdocs/config/version-2.0/examples/migration-receiver-v2.yaml \
  ./migration-receiver-v2.yaml

obi config validate --mode=receiver ./migration-receiver-v2.yaml
```

Receiver migration models the trace and metric sinks supplied by the
Collector. It therefore accepts a valid legacy component body such as
`open_port: "8080"` without inventing a standalone exporter. It emits every
capture child flattened beside `version`. Explicit v1
`otel_traces_export`, `otel_metrics_export`, and `prometheus_export` sections
are rejected because the Collector pipeline must own those exporters:

```text
receivers:
  obi:
    version: "2.0"
    policy:
      default_action: exclude
    rules:
      - action: include
        match:
          process:
            open_ports: "8080"
    # ...every other migrated capture child...
```

Before reporting success, the command round trips the exact flattened capture
body it will emit. Legacy receiver fields whose v2 destinations are
standalone-only—such as Kubernetes/attribute enrichment, name resolution, log
correlation, daemon logging, and internal metrics—are rejected with their v1
paths. Move those responsibilities to Collector processors or service
telemetry; do not discard them merely to make migration pass.

There is no `capture:` wrapper in the receiver component. Do not copy
standalone `enrich`, `correlation`, or `daemon`; receiver validation rejects
them. Do not copy top-level standalone providers into the receiver component.
Configure exporters and resource processing in the Collector service
pipelines.

The
[legacy receiver input](examples/migration-receiver-v1.yaml) and its
[generated v2 result](examples/migration-receiver-v2.yaml) form the tested
receiver pair. The result is a complete receiver component body, not a whole
Collector document. Embed it under `receivers.obi` after validation.

For a full Collector document, see the
[OBI Collector example](../../../examples/otel-collector/config.yaml). The
Collector receiver retains v1 fallback when its release documents that
compatibility, but a malformed recognized v2 receiver configuration is not
reinterpreted as v1.

## Canary and verify

Do not deploy the generated standalone file until the target release advertises
runtime v2 loading.

For a canary:

1. deploy the new OBI release and v2 file to one representative instance;
2. preserve the same permissions, kernel, exporter destinations, resource
   metadata, and secret environment;
3. confirm OBI starts without configuration warnings and exporters connect;
4. exercise known HTTP, gRPC, database, messaging, and network paths;
5. compare v1 and v2 over the same traffic window.

At minimum compare:

- discovered and excluded processes;
- trace and metric export rates and error/drop counters;
- `service.name`, `service.namespace`, Kubernetes, and host attributes;
- span names, normalized routes, and route-cardinality bounds;
- filtered methods, paths, addresses, and other sensitive attributes;
- enabled protocols, span metrics, service graphs, network flows, and network
  statistics;
- OBI self-instrumentation and already-instrumented-service exclusions;
- shutdown, profiling, internal metrics, and log format where configured.

Validation cannot perform these runtime checks.

## Roll back

Keep the old binary or image, v1 file, external environment, and deployment
manifest until the canary and production observation window have completed.

If startup or telemetry differs:

1. stop the v2 canary;
2. restore both the old OBI version and its v1 file;
3. restore the original environment and manifest;
4. verify telemetry returns to the recorded v1 baseline;
5. retain the generated YAML and migration report for diagnosis.

Do not use a v2 file with a release that only supports the v1 runtime loader.
Do not convert the generated v2 file back into v1 by hand; the saved source is
the rollback artifact.

## Publication and release linkage

This operator guide is published from the repository and linked from the root
[README](../../../README.md), the [developer documentation index](../../README.md),
and the [Config v2 reference](config-v2.md). Config v2 remains behind the
atomic release gate until its runtime, CLI, receiver, artifacts, and
documentation ship together.

The release process requires the first enabling release's notes to link this
guide and identify its supported deployment modes, v1 compatibility, and
migration limitations. It also requires those notes to be linked from the
[Config v2 release gate](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2251)
and the
[stable v1.0 release epic](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1133).
Do not infer an enabling version from this guide; use only an explicit release
note.

## Known limitations and deferred work

- Public standalone loading is part of the atomic
  [Config v2 release gate](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2251);
  track [#2535](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2535)
  and [#2682](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/2682)
  before choosing a release.
- Protocol- and signal-specific filter narrowing remains unresolved in
  [#1282](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1282).
  Migrated filters must remain fanned out and equal.
- Per-workload pipelines, exporters, metric views, and sampling are outside
  the current v2 migration contract and remain tracked in
  [#923](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/923).
- The supported top-level OpenTelemetry declarative subset is intentionally
  narrow. Schema acceptance alone does not imply runtime application of every
  upstream field.
- The v1 removal date is not decided. Follow the release notes rather than
  assuming that v1 fallback has ended.

Do not resolve these open contracts by inventing configuration fields. Keep
the generated parity configuration or postpone migration when a required
behavior is not supported.

## References

- [Config v1 reference](../CONFIG.md)
- [Config v2 design and field mapping](config-v2.md)
- [OBI Config v2 extension schema](obi-extension.schema.json)
- [Runnable standalone Config v2 example](examples/default-configuration.yaml)
- [Authored Config v2 default-values reference fragment](examples/default-values-reference.fragment.yaml)
- [Config v2 release gate](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2251)
- [Migration documentation issue](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1758)
