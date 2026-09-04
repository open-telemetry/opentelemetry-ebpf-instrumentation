# OBI semantic-convention registry

This registry (see `manifest.yaml`) extends the upstream OpenTelemetry
semantic-conventions registry with the signals and attributes OBI emits in
addition to — or as overrides of — the standard semconv set. Together with the
upstream dependency it forms the complete contract of what OBI emits

## Overriding an upstream definition

Weaver has **no precedence or merge semantics** between a local group and the
groups a dependency contributes to the resolved registry (OBI's group files
`import` the definitions they refine and `ref` the attributes they emit, both
of which pull the upstream groups in). When the same attribute id is
declared by more than one group, live-check silently resolves
the duplicate in favor of the group whose id sorts **last lexicographically** —
including the upstream `span.*` / `metric.*` groups that `ref` an attribute
and therefore carry an embedded copy of its upstream definition. Tracked
upstream in <https://github.com/open-telemetry/weaver/issues/1578>.

Until weaver defines local-wins override semantics, every override in
`groups/` must follow these rules:

1. **Group id**: use the `x.obi.<namespace>` prefix so the override sorts
   after every upstream group id (`registry.*`, `span.*`, `metric.*`, …) and
   wins the resolution. Do not rename an override to something that sorts
   earlier, and do not reuse an upstream group id (a same-id redefinition
   loses the tie to the dependency AND trips `DuplicateGroupId` in
   `registry check`).
2. **Replacement, not merge**: an override REPLACES the upstream attribute
   definition wholesale. An enum override must therefore carry the FULL
   upstream member list plus OBI's extensions; when bumping the semconv
   dependency, re-sync the upstream members verbatim from
   `.deps/upstream-<version>/model/<ns>/registry.yaml`. A missing member
   resurfaces as an `undefined_enum_variant` failure in the weaver-validated
   suites, so drift is caught, not silent.
3. **Expected lint duplicates**: `weaver registry check` flags each override
   as a `DuplicateAttributeId` error even though
   live-check resolves it. Each expected duplicate is allowlisted — tightly,
   by attribute id and group pair — in `scripts/lint-schema-filter.jq`
   (covered by `scripts/lint_schema_filter_test.go`). Anything else still
   fails `make lint-schema`.

## Group ids

A metric group's id is `metric.obi.<metric_name>`, derived from the metric it
declares so the two cannot drift apart.

Do not rely on that id sorting after the upstream `metric.<metric_name>` group.
It does for most namespaces, but `obi.` loses to any namespace ordering after
it: `metric.obi.rpc.client.call.duration` sorts before
`metric.rpc.client.call.duration`, and the `target.info` / `traces.*` ids lose
to `metric.t*` the same way. What keeps the local definition authoritative is
that live-check runs without `--include-unreferenced`, so unreferenced upstream
groups drop out of resolution and only one group per metric name survives.
`TestOBIMetricOverridesResolveToLocalNarrowedDefinition` fails closed if that
stops holding.

Attribute groups declaring OBI-own attributes use `registry.obi.<namespace>`;
overrides of an upstream attribute use `x.obi.<namespace>` per the rules above.

## Two override styles

- **Closed enum, extended**: the upstream value space is enumerable and OBI
  intentionally emits extra members (e.g. `messaging.system` gains
  `amqp`/`mqtt`/`nats`, `db.system.name` gains `aerospike`). The override
  re-declares the enum with upstream members + OBI's, so weaver still flags
  any value outside the combined list — bug values like an empty string or
  `unknown` are deliberately NOT declared on these overrides and keep failing
  the suites. This applies to overrides of upstream enums only. OBI's own
  attributes (`direction`, `reason`, `network.tcp.handshake.role`) do declare
  `unknown`, where it is a meaningful classification rather than a bug: OBI
  genuinely cannot always determine a flow's direction or why a handshake
  failed.
- **Open-ended value space, re-typed as string**: upstream declares an enum,
  but the real value space is unbounded by design — domain-specific error
  codes (`error.type`) or provider/MCP operation vocabularies
  (`gen_ai.operation.name`). Enumerating these is impossible, so the override
  re-types the attribute as a plain `string` with examples. Weaver then
  validates presence/type but not membership. For these attributes the
  emitters must still omit the attribute instead of sending an empty value;
  that guarantee lives in the emitter unit tests
  (`pkg/appolly/app/request/span_getters_test.go`,
  `pkg/export/otel/traces_test.go`), not in weaver.

Values OBI merely passes through from user configuration (e.g.
`deployment.environment.name` from a workload's `OTEL_RESOURCE_ATTRIBUTES`)
are NOT overridden: the integration tests must configure values that satisfy
the upstream conventions instead.
