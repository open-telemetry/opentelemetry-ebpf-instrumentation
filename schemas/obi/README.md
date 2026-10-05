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
  that produces it, or add a span type for a new branch together with its
  live-check matcher in `.weaver.toml` (see below), and a case to
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
  `emitted_contract_test.go` match their span type exactly; the live-check
  matchers select each of those spans as its own type and no other; OBI's
  copies of upstream metrics keep upstream's unit, instrument and stability,
  and win resolution over the upstream definition; every signal and attribute
  definition conforms to upstream as described under "Conformance with
  upstream".

Checked only when an integration suite that runs weaver exercises it:

- Weaver live-check sees what OBI actually sent and fails on an undeclared
  metric (`missing_metric`), an undeclared attribute (`missing_attribute`), an
  enum value the registry does not list, or a `required` metric attribute that
  is missing.
- Each span is matched to its span type by the matchers in `.weaver.toml` and
  checked against that type; a span no matcher selects fails the suite. Span
  names are compared with the type's name templates, and a mismatch fails the
  suite.

Not enforced today:

- There is no deterministic check that every metric in
  `pkg/export/attributes/metric.go` is declared; an undeclared metric fails
  only once a weaver-validated suite emits it.
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
   fails `TestAttributeDefinitionsConformToUpstream`, so drift is caught, not
   silent.
2. **Documented in an `x.obi.<namespace>` attribute group**: the file that
   defines an override also declares a public `x.obi.<namespace>` attribute
   group referencing it, with a brief that says what the override changes. The
   generated reference lists overrides under those groups.

## Conformance with upstream

Live-check cannot match a signal to an upstream span or refinement, so OBI
redeclares the signals it emits. Each copy names what it implements, and
`internal/schemacheck/upstream_conformance_test.go` compares it with upstream.

A metric declared under an upstream metric's name implements that metric, with
no annotation. Every span, and every other metric outside the `obi.`
namespace, sets `annotations.obi.upstream`:

- one upstream span type, refinement id or metric name, e.g.
  `upstream: http.client`. A span may also name an upstream attribute group,
  for conventions upstream defines only as attribute groups, such as messaging
  in semconv v1.41.0 (`upstream: messaging.kafka`);
- a list, when the signal also follows further conventions, e.g.
  `upstream: [messaging.aws.sqs, messaging.attributes]`. The first
  entry is the signal OBI implements. A per-system span also names the generic
  span upstream states it in prose, so the system name the generic span
  requires is checked: `upstream: [rpc.grpc.call.client, rpc.call.client]`;
- `none` with an `upstream_reason`, when upstream defines no such signal.

The test fails when:

- a signal names no upstream signal, sets `none` without an
  `upstream_reason`, or carries an `upstream_reason`, `upstream_omits`,
  `upstream_relaxes` or `upstream_extras` that its link makes meaningless;
- a named upstream signal does not exist in the pinned semconv release;
- a named signal requires or conditionally requires an attribute that OBI
  does not declare, or declares at a lower level: `recommended` or `opt_in`,
  or `conditionally_required` where upstream makes it `required`. Where several
  named signals list the same attribute, the one named first sets its level,
  so Elasticsearch keeps `db.namespace` recommended although the generic
  database span conditionally requires it. When the condition can never
  hold for OBI's signal, `annotations.obi.upstream_omits` on the signal names
  the attribute with the reason, e.g. a consumer group on a producer span.
  When OBI declares it at a lower level because it cannot always observe it,
  or deliberately keeps it optional, `annotations.obi.upstream_relaxes` names
  it with the reason, e.g. `server.address` read from a connection a BPF event
  may not carry, or `dns.question.name` kept opt-in for its cardinality;
- OBI declares an upstream attribute that none of the named signals lists,
  such as `http.route` on a client metric, unless
  `annotations.obi.upstream_extras` on the signal names it with the reason it
  belongs there. The attributes of the internal `attributes.obi.transport`
  group (peer, client and server address and port, protocol version, peer
  service) carry a single shared reason and may appear on any span without an
  entry, but not on a metric, where they multiply series;
- an attribute definition of an upstream key changes its type, brief or
  stability or drops an enum member, or retypes an enum as a primitive without an
  `annotations.obi.upstream_deviation` reason on the definition;
- OBI defines an attribute in a namespace upstream owns, outside `obi.`,
  without an `upstream_deviation` reason on the definition.

The test also fails on an `upstream_omits`, `upstream_relaxes` or `upstream_extras` entry that no
longer waives or justifies anything, so an entry is removed once OBI or
upstream changes. OBI's own `obi.*` attributes, and requirement levels of
attributes upstream makes `recommended` or `opt_in`, are not compared.

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
`attributes.obi.http.server.common` — so it stays out of the attribute pages, which
document what OBI defines.

## Span names

Every span declares how OBI names it. `name.templates` lists the templates in
the order OBI tries them: the first whose attributes are all present, non-empty
and not `_OTHER` gives the name. A span whose name uses a value OBI does not
emit as an attribute describes it in `name.note` instead. Live-check compares
the name of each span with its templates through the `span_name_mismatch`
policy in `.live_check_policies/`.

## Live-check matchers

A span carries no identifier of its own, so `.weaver.toml` declares one
`[[live-check.matchers]]` entry per span type, selecting a span by its kind
and the attributes that tell its type apart. Matchers are evaluated in order
and are mutually exclusive; `TestEmittedSpansMatchTheirDeclaredSpan` in
`internal/schemacheck` feeds representative spans through live-check and fails
when a span matches any type other than its own. A new span type needs a
matcher, or the weaver-validated suites fail on its unmatched spans.

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
