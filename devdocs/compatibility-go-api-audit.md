# Go API checker policy audit

This audit covers static Go source APIs. It does not establish compliance for
CLI/configuration behavior, stable telemetry, packaging, support requirements,
or Go toolchain support. Those remain separate stages in [#4269].

The governing sources are [VERSIONING.md](../VERSIONING.md#go-module-api), the
[v1.0.0 stable-surface declaration][release], [TELEMETRY.md](../TELEMETRY.md), and
[SUPPORT_MATRIX.md](../SUPPORT_MATRIX.md). The release declaration takes precedence
over the tagged policy's introductory pre-v1 Development wording.

## Policy and executable expectations

All tests below live under [`internal/tools/compatcheck`](../internal/tools/compatcheck).
`make test-compat` runs them with the race detector. Consumer fixtures compile
against both snapshots; prohibited examples must fail against the changed API.

| Policy case | Expected result | Regression coverage |
| --- | --- | --- |
| Add OBI functions, concrete methods, types, fields, constants, variables, or packages | No finding; minor when newly added since the latest release | `TestPRAndReleaseResults`, `TestPackageAdditionAndRemoval` |
| Compatible dependency update | No finding; patch permitted | `TestDependencyUpdateClassification`, including a separate module under the OBI path prefix |
| Exposed dependency API becomes incompatible | Major; affected API reported | `TestDependencyUpdateClassification` |
| Implementation/private-layout refactor | No finding; patch permitted | `TestPublicAPIConsumers`, `TestPRAndReleaseResults` |
| Move a type while preserving its exported alias | No incompatible finding | `TestAliasMoveConsumers` |
| Replace an alias with a distinct defined type | Major | `TestAliasReplacedByDefinedType` |
| Remove exports, rename a package, or change function signatures | Major | `TestPublicAPIConsumers`, including parameter, result, and variadic signatures |
| Add methods to an existing interface | Major | `TestPublicAPIConsumers/exported_interface_method_addition` |
| Change an exported array field's type or lose comparability | Major | `TestPublicAPIConsumers/array_field_length`, `comparability` |
| Narrow generic constraints | Major | `TestPublicAPIConsumers`, `TestAttributionOfExposedConstraint` |
| Relax generic constraints or rename their parameters | No incompatible finding | `TestPublicAPIConsumers`, including recursive constraints |
| Constant value changes without proof of incompatible meaning | Separate unclassified comparison; incomplete assessment | `TestPRAndReleaseResults/constant_value_needs_contract_review` |
| Name an anonymous struct containing private fields | Separate unclassified comparison; incomplete assessment | `TestUnclassifiedPrivateStructIdentity`, `TestPRAndReleaseResults` |
| Failed acquisition, verification, extraction, or type capture | Incomplete; never a compatibility pass | `TestInvalidInputProducesIncompleteReport`, `TestEmptyPublicSurfaceFails`, release-client tests |

`TestLoadAPI` verifies root-module membership, architecture selection, exclusion
of commands, test files, internal-only roots, and nested modules. Public packages
intended for downstream testing remain public APIs, as documented by
[`pkg/test/integration`](../pkg/test/integration/doc.go).

`TestPRAndReleaseResults` also checks attribution, JSON/text output, and exit
statuses: permitted additions produce no findings; existing problems do not
become PR problems; proposed releases still assess the entire candidate.

## Accounting for the reported 285 entries

The audited comparison is immutable release `v1.0.0`
(`d23be0d6b709c7e7047067c7e32c2500deee51dd`) against target
`c37573317025d9c20821b8dcd3a84a098ee5ab4c`. The original reports are attached to
[CI run 44169366698][original-run]. Counts are per architecture and match on
Linux amd64 and arm64.

| Raw changes | Count | Correct treatment |
| --- | ---: | --- |
| Additions: 93 fields, 26 concrete methods, 36 constants, 40 functions, 39 types, 8 variables, 3 packages | 245 | Permitted Go API additions; no findings |
| Added methods on `Route53Client` | 2 | Incompatible interface extension |
| Changed exported `Pad` array field types | 4 | Incompatible source types, including aliases |
| Removed `SymbolMatcher` exports | 4 | Incompatible removals |
| Lost `DotnetRuntimeMetricSnapshot` comparability | 1 | Incompatible type semantics |
| Anonymous PID structs replaced with `BpfPidInfoT` | 27 | Unclassified; underlying struct shapes match |
| Changed `BpfRingbufIdRINGBUF_COUNT` and `FeatureAll` values | 2 | Unclassified; value differences alone do not prove incompatible meaning |

The declaration audit resolves every addition against the old and new Go type
graphs and verifies that all 26 added methods have concrete receivers. Two added
fields belong to an AWS dependency; compatible dependency updates may remain
patches. Module ownership comes from Go's module metadata, rather than import
path prefixes, so independently versioned modules retain their own identity.

The 11 incompatible API declarations fall into four groups. Consumer compilation
against the released source succeeds; the same source fails against the target:

- `Route53Client.ListHostedZones` and `ListHostedZonesByVPC`: an implementation
  of the old interface no longer satisfies the extended interface.
- `BpfHttpRequestTraceT.Pad` and `HTTPRequestTrace.Pad`: `[11]uint8` became
  `[9]uint8`; `BpfNodeSpanEventT.Pad` and `NodeSpanEvent.Pad`: `[2]uint8` became
  `[1]uint8`. Assignments to the original array types stop compiling.
- `ProbeDesc.SymbolMatcher`, `SymbolMatcher`, `SymbolMatcherContains`, and
  `SymbolMatcherExact`: references to these exports stop compiling.
- `DotnetRuntimeMetricSnapshot`: equality comparisons stop compiling after a
  map field is added.

These are affected API paths; aliases can share an underlying source change.
The checker does not compare ABI offsets or require stable private layouts.
The 29 unclassified comparisons establish neither compatibility nor a policy
violation. They keep the full-candidate release assessment incomplete and must
be resolved before enforcement is activated.

[#4269]: https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/4269
[release]: https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/tag/v1.0.0
[original-run]: https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/runs/44169366698
