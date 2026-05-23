# OBI Configuration Migration Plan

Status: Draft for discussion  
Audience: OBI maintainers and contributors  
Scope: migration behavior, validation policy, rollout strategy, and tooling expectations

This document defines how the project and users will migrate configuration from the v1 to v2 model safely and predictably.

Goals:

- Deterministic parsing and validation for v2 inputs.
- Consistent behavior across standalone host and collector receiver host.
- Actionable diagnostics for operators before rollout.

## v2 Configuration Parsing

A new configuration package will be added. Its purpose will be to provide:

- Parsing functionality of the `extension.obi` portion of the `v2` configuration
- Export types representing the OBI configuration

Using this new package, both the OBI command and the collector receiver will parse user provided configuration.
It will be up to these callers to determine:

- how to fallback to v1 support when the parser informs it that the input format is v1
- how to setup the SDK which is outside the scope of the v2 configuration package

### Integration with `otelconf`

It is assumed that users that need SDK will use the `go.opentelemetry.io/contrib/otelconf` package to parse top-level objects of the declarative config accordingly.
SDK object construction is outside the v2 configuration package scope and configuration for that portion of the configuration will be ignored.
The OBI v2 configuration package only parses and validates `extensions.obi`.
It does not merge or translate `instrumentation/development` into OBI-owned settings.

### Deployment-mode validation

`extensions.obi` has a two-tier structure:

- `capture`: receiver-embeddable — valid in **all** deployment modes.
- `enrich`, `correlation`, `daemon`: **standalone-mode only** — not valid in Collector receiver deployments.

When parsing configuration for a Collector receiver context, the v2 parser will reject any configuration that includes standalone-only sections (`enrich`, `correlation`, `daemon`) and surface a structured error with remediation guidance.
This validation is structural: the parser does not rely on a `deployment:` flag in the config — the section presence itself is the indicator.

When parsing for a standalone context, all sections are valid.
The presence of `enrich`, `correlation`, and `daemon` is not required — these sections have defaults when omitted.

### Backward compatibility behavior

Based on the structure of the configuration, the version of that configuration can be determined from:

- Root `version` identifies OTel declarative document contract.
- `extensions.obi.version` identifies OBI extension contract.

From this, the v2 configuration package will behave as follows:

- The v2 parser only accepts supported v2 configuration contracts.
- If config is not v2 (including detectable v1 shape), return a structured version error with actionable guidance.
- Caller decides fallback behavior (for example, route to legacy v1 parsing/setup path).
- The v2 parser does not perform legacy setup or implicit v1→v2 translation.
- If both `extensions.obi` and `instrumentation/development` are present, OBI behavior is sourced from `extensions.obi` only.

Going forward, the configuration package may need to add support for future versions (i.e. v3).
It will be structured in a way to seamlessly support these new configuration files.

### Why these responsibilities belong to the caller

The v2 configuration package is deliberately a parsing and validation layer — not a setup or migration layer.
This separation was a conscious design choice:

- Version detection and fallback routing are host-specific concerns. The standalone `obi` command and the Collector receiver have different error surfaces, logging facilities, and user communication channels. Centralizing routing logic in the package would force one error-handling strategy onto both hosts.
- A parser that silently attempts v1→v2 translation would hide version mismatches from operators. Explicit versioning with a structured error gives the caller — and ultimately the operator — full visibility into what version was provided and what was expected.
- Keeping the package scope narrow (parse + validate `extensions.obi`) makes it testable in isolation, without requiring a full OBI host context.

## Migration CLI

The `obi` command needs to have a configuration migration tool added to it.
It needs to support semantics like the following.

```shell
obi config migrate --from v1 --to v2
```

- Read v1 or mixed legacy input.
- Produce canonical v2 output.
- Emit a mapping report (moved, renamed, split/fan-out, inverted semantics).
- Emit warnings for deprecated aliases.
- Fail only when rewrite is non-deterministic.

### What non-deterministic means

Most v1→v2 mappings are 1:1 moves and renames (see the [v1→v2 mapping table](./config-v2.md#compatibility-and-mapping-from-v1)).
A small set of mappings are structurally non-trivial:

- **Fan-out**: `filter.application` fans out to per-protocol `capture.instrumentation.<protocol>.filters.{traces,metrics}`. The migration tool applies the v1 value as the default for all protocols and emits a mapping report explaining the fan-out.
- **Shape change**: `discovery.excluded_linux_system_paths` and `discovery.exclude_otel_instrumented_services` are rewritten into structured rule entries under `capture.rules`. The migration tool generates these entries and flags them for operator review.
- **Inverted boolean**: `discovery.skip_go_specific_tracers: true` maps to `capture.runtimes.go.enabled: false`. The migration tool applies the inversion and emits a note.
- **Sampler**: `otel_traces_export.sampler.name` and `.arg` migrate to `tracer_provider.sampler`. Simple cases (e.g., `always_on`, `trace_id_ratio_based`) map directly to built-in OTel declarative sampler types. Custom or workload-specific sampler configs may require operator intervention and use of the `obi_rule_based` sampler plugin.

Only mappings that cannot be resolved without operator input cause migration to fail with a non-deterministic error.

## Validation CLI

The `obi` command needs to have a configuration validation tool added to it.
It needs to support semantics like the following.

```shell
obi config validate ./path/to/config
```

- Read v1 or later configuration as input via an argument
- Parse and validate the configuration
- Emit warnings for invalid configuration detected
- Emit warnings for deprecated configuration versions
- In receiver context (detected via flag or auto-detection), reject standalone-only sections (`enrich`, `correlation`, `daemon`) with an explicit error identifying the section and remediation steps

## Rollout strategy

### Phase 0 — Build contract and tooling

- Finalize v2 configuration artifacts: schema, example, migration doc, parity check.
- Implement the new `extensions.obi` v2 configuration package (parse + validate `capture`, `enrich`, `correlation`, `daemon`).
- Implement and ship the `obi_rule_based` sampler plugin (referenced via `tracer_provider.sampler`) with documented rule semantics.
  - This is required before v2 GA: per-workload sampling is a first-class use case and must be addressable without requiring workarounds.
  - Integrate sampler plugin registration/wiring in OBI startup paths (standalone and receiver embedding paths where applicable).
- Implement migration CLI.
- Implement validation CLI.

### Phase 1 — Freeze and identify

- Freeze v1 key surface except critical fixes.
- Lock version-detection and compatibility behavior.
- Communicate v1 freeze to users and direct them to migration tooling.

### Phase 2 — Dual-read period

- Attempt v2 parser first; on explicit not-v2 result, invoke legacy parser path.
- Both parsers active simultaneously; no user-visible behavior change for v1 configs.
- Use this phase to gather feedback on v2 ergonomics and migration tooling.

### Phase 3 — v2-first default

- Default docs/examples/CI to v2.
- Deprecate the v1 configuration. Warn users in logs and validation output, and tell them how to migrate with tooling.
- v1 parsing remains available but is no longer the recommended path.

### Phase 4 — v1 retirement

- Remove v1 parsing. Error on v1 input, and tell users how to migrate with tooling.

### Why this phased approach

The dual-read period (Phase 2) is the key risk mitigation:

- Users on v1 configs continue working without changes during v2 stabilization.
- The version-detection boundary is exercised in production before v1 parsing is removed.
- Feedback on v2 ergonomics and migration tooling can be incorporated before the v2-first default.

A hard cutover (skip Phase 2) was considered and rejected because it places migration burden on operators with no fallback path if the v2 parser has edge cases. The phased approach lets operators validate at their own pace before the v1 path is gone.

## Operator-facing quality bar

Before rollout, migration UX should ensure:

- Every failure has clear remediation text.
- Every warning identifies exact source key and target key.
- Resolved/effective config is inspectable.
- Same input produces same output across environments.
- Receiver-context validation clearly identifies which standalone-only sections are invalid and why.

## Open decisions

- Timeline for final v1 removal after v2 GA.
