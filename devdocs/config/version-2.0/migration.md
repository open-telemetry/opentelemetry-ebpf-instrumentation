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

A new configuration package will be added. It's purpose will be to provide:

- Parsing functionality of the `extension.obi` portion of the `v2` configuration
- Export types representing the OBI configuration

Using this new package, both the OBI command and the collector receiver will parse user provided configuration.
It will be up to these callers to determine:

- how to fallback to v1 support when the parser informs it that is then input format
- how to setup the SDK which is outside the scope of the v2 configuration package

### Integration with `otelconf`

It is assumed that users that need SDK will use the `go.opentelemetry.io/contrib/otelconf` package to parse top-level objects of the declarative config accordingly.
SDK object contruction is outside the v2 configuration package scope and configuration for that portion of the configuration will be ignored.
The OBI v2 configuration package only parses and validates `extensions.obi`.
It does not merge or translate `instrumentation/development` into OBI-owned settings.

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

## Rollout strategy

### Phase 0 — Build contract and tooling

- Finalize v2 configuration artifacts.
- Implement migration CLI.
- Implement validation CLI.

### Phase 1 — Freeze and identify

- Freeze v1 key surface except critical fixes.
- Lock version-detection and compatibility behavior.

### Phase 2 — Dual-read period

- Attempt v2 parser first; on explicit not-v2 result, invoke legacy parser path.

### Phase 3 — v2-first default

- Default docs/examples/CI to v2.
- Deprecate the v1 configuration. Warn users, and tell them how to migrate with tooling.

### Phase 4 — v1 retirement

- Remove v1 parsing. Error, and tell users how to migrate with tooling.

## Operator-facing quality bar

Before rollout, migration UX should ensure:

- Every failure has clear remediation text.
- Every warning identifies exact source key and target key.
- Resolved/effective config is inspectable.
- Same input produces same output across environments.

## Open decisions

- Timeline for final v1 removal after v2 GA.
