# OBI semantic-convention registry

This registry (see `manifest.yaml`) extends the upstream OpenTelemetry
semantic-conventions registry with the signals and attributes OBI emits in
addition to — or as overrides of — the standard semconv set. Together with the
upstream dependency it forms the complete contract of what OBI emits

Every file under `groups/` uses weaver's `definition/2` format: attributes are
defined under `attributes:`, and spans, metrics and attribute groups reference
them with `ref:` (or a whole internal attribute group with `ref_group:`).

## Adding telemetry

Every metric, span or attribute OBI starts emitting over OTLP must be declared
here in the same change:

- **An upstream metric emitted unchanged** (same name, unit, instrument and
  data-point attributes): import it in the domain's `imports.yaml`, as
  `groups/nodejs/imports.yaml` and `groups/dotnet/imports.yaml` do.
- **An upstream metric OBI emits differently**, or one of OBI's own: add it to
  the `metrics:` list of `groups/<domain>/metrics.yaml`, listing every attribute
  the metric's `attr_defs.go` section can carry, each with a requirement level.
- **A span**: add its attributes to the `obi.*` span type of the emitter branch
  that produces it, or add a span type for a new branch, and a case to
  `internal/schemacheck/emitted_contract_test.go`.
- **An attribute upstream does not define**: declare it under `attributes:` in
  the domain's `registry.yaml`.

Then run `make lint-schema` and `make generate-schema-docs`, and make sure an
integration suite that runs weaver exercises the new telemetry (see below).

## What validation covers

Checked on every change, without running OBI:

- `make lint-schema`: the registry resolves and is well-formed.
- `internal/schemacheck`: every signal attribute declares a requirement level;
  the span attributes the exporter emits for each case in
  `emitted_contract_test.go` match their span type exactly; OBI's copies of
  upstream metrics keep upstream's unit, instrument and stability, and win
  resolution over the upstream definition.

Checked only when an integration suite that runs weaver exercises it:

- Weaver live-check sees what OBI actually sent and fails on an undeclared
  metric (`missing_metric`), an undeclared attribute (`missing_attribute`), an
  enum value the registry does not list, or a `required` metric attribute that
  is missing.

Not enforced today:

- There is no deterministic check that every metric in
  `pkg/export/attributes/metric.go` is declared; an undeclared metric fails
  only once a weaver-validated suite emits it.
- Spans are not matched to a span type by live-check, which checks each span
  attribute against the registry as a whole. Span type membership, span kind
  and required span attributes are checked only for the cases in
  `emitted_contract_test.go`, and span names are not checked.
- `conditionally_required` conditions are prose and are not evaluated.
- Output specific to the Prometheus exporter is not described by the registry.

## Overriding an upstream definition

An attribute defined in this registry takes precedence over the definition of
the same key in the upstream dependency: weaver resolves every `ref` against
the registry's own `attributes:` first and only then looks in its
dependencies. An override is therefore a plain definition, under
`attributes:`, of the upstream key, and every signal in this registry that
references the key sees OBI's definition. Refinements cannot express these
overrides, because a refinement of an attribute may change its brief, note,
examples, annotations and requirement level, but not its type or enum members.

Every override in `groups/` follows these rules:

1. **Replacement, not merge**: an override REPLACES the upstream attribute
   definition wholesale. An enum override must therefore carry the FULL
   upstream member list plus OBI's extensions; when bumping the semconv
   dependency, re-sync the upstream members verbatim from
   `.deps/upstream-<version>/model/<ns>/registry.yaml`. A missing member
   resurfaces as an `undefined_enum_variant` failure in the weaver-validated
   suites, so drift is caught, not silent.
2. **Documented in an `x.obi.<namespace>` attribute group**: the file that
   defines an override also declares a public `x.obi.<namespace>` attribute
   group referencing it, with a brief that says what the override changes. The
   generated reference lists overrides under those groups.

## Ids

A metric is identified by its `name`, and a span by its `type`, which carries
the `obi.` prefix so it cannot collide with an upstream span type.

A metric OBI redeclares from upstream keeps the upstream name. The local
definition stays authoritative because live-check resolves without
`--include-unreferenced`, so the upstream metric, which nothing in this
registry imports, drops out of resolution.
`TestOBIMetricOverridesResolveToLocalNarrowedDefinition` fails closed if that
stops holding.

Attribute groups referencing OBI-own attributes use `registry.obi.<namespace>`;
those referencing overrides of an upstream attribute use `x.obi.<namespace>`
per the rules above. An attribute set shared by several spans is an internal
attribute group named `attributes.obi.<shared part>` — the messaging spans
share `attributes.obi.messaging.common` and the HTTP server spans
`attributes.obi.http.server` — so it stays out of the attribute pages, which
document what OBI defines.

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
  codes (`error.type`) or provider operation vocabularies
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
