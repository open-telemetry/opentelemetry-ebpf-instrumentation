# Versioning

This document defines the versioning and stability policy for OpenTelemetry eBPF Instrumentation (OBI).

OBI follows [Semantic Versioning 2.0.0](https://semver.org/) and Go semantic import versioning.

## Current status

OBI is currently in Development.

All current OBI user-facing surfaces are unstable by default, including:

- the `go.opentelemetry.io/obi` Go module
- the `obi` binary and published container image contents
- published container images corresponding to a release tag
- configuration files, configuration schema, flags, and environment variables
- emitted telemetry
- build-time support for Go versions when consuming OBI as a Go module
- runtime support for kernels, libraries, runtimes, and other instrumented environments

Adding this document does not change the project's maturity. It records the current shared understanding of the project.

### What Development means

While OBI remains in Development:

- users should expect to review release notes before upgrading between minor releases
- minor releases may include breaking changes to configuration, defaults, behavior, telemetry, supported environments, and other user-facing surfaces
- users should pin to semver release tags and should not treat `latest` as a stable or compatibility tag
- dashboards, alerts, and downstream processors should not assume telemetry continuity across `v0` minor releases unless a surface is explicitly documented as stable
- consumers of the Go module should expect build-time compatibility expectations to evolve until stable guarantees are explicitly declared

## Release scope

The default policy is to keep the core OBI release line versioned together.

A release tag `vX.Y.Z` identifies one coherent core OBI release across:

- the root Go module
- release binaries
- release container images
- the generated configuration schema and documented configuration behavior

If ancillary tooling is later split into separately versioned modules, this document MUST identify which modules remain part of the core OBI release line and which modules are versioned separately.

## Version numbers before v1

OBI remains in `v0` until the project is ready to make stable compatibility guarantees for explicitly declared stable surfaces.

While OBI is in `v0`:

- breaking changes are allowed in minor releases
- patch releases are for backward-compatible fixes, security fixes, documentation, packaging corrections, and similar low-risk changes
- pre-release tags such as `-rc1` may be used for release candidates

For `v0` releases:

- bump the minor version for incompatible changes to public packages, flags, config, defaults with user-visible behavioral impact, telemetry shape or naming, support expectations, or release artifact behavior
- bump the patch version for backward-compatible fixes only

## Compatibility and release rules after v1

The rules in this section are forward-looking. They apply only after OBI declares a surface stable.

### Major version bumps

A major version bump is required for any breaking change to a stable surface. This includes:

- Go module API changes such as removing or renaming exported packages, functions, methods, types, fields, or constants, or changing their behavior incompatibly
- changes that require a new semantic import version path for `v2+`
- CLI changes such as removing or renaming commands, subcommands, flags, flag values, environment variables, or configuration locations, or changing their meaning incompatibly
- configuration changes such as removing or renaming fields, changing field types, changing serialized names, making validation stricter for previously valid configurations, or changing defaults in a way that changes behavior for existing valid configs
- emitted telemetry changes such as renaming or removing stable spans, metrics, resource attributes, span attributes, metric names, metric units, or attribute keys in ways that break queries, alerts, dashboards, or downstream processors
- binary and image contract changes such as materially changing invocation or packaging expectations, or changing the functional contract of a stable image tag
- support matrix changes that drop support for a previously supported kernel, distro, architecture, container environment, language runtime, or instrumented library version, unless that support was explicitly documented as Development-only or otherwise outside the compatibility contract

### Minor version bumps

A minor version bump is allowed for backward-compatible additions and behavior-preserving improvements to stable surfaces. This includes:

- adding new exported Go APIs
- adding new commands, flags, environment variables, and configuration fields that are optional
- adding new telemetry, attributes, or instrumentation coverage without changing the meaning of existing stable telemetry
- broadening the supported platform or runtime matrix
- adding new binaries or images without altering the contract of existing ones
- changing defaults only when the old behavior remains available and existing valid configurations continue to behave compatibly by default

### Patch version bumps

A patch version bump is allowed only for backward-compatible fixes that do not require user migration. This includes:

- bug fixes that preserve public contracts
- security fixes
- packaging or build fixes that do not change the stable artifact contract
- documentation-only changes
- dependency updates that do not create observable incompatibility in stable surfaces

### Surface-specific rules after v1

#### Go module API

OBI does not guarantee forward ABI compatibility for Go module consumers. Unless explicitly stated otherwise, compatibility guarantees for Go packages are source-level API guarantees, and consumers should expect to recompile against the version they use.

Allowed in minor releases:

- additive exported APIs
- implementation fixes
- internal refactors
- new packages

Not allowed before a major release:

- removing exported symbols
- adding methods to exported interfaces
- changing function signatures
- changing type semantics incompatibly
- moving packages incompatibly
- adding required dependencies that create import path or version conflicts for consumers

#### CLI and environment variables

Allowed in minor releases:

- new commands
- new optional flags
- new optional environment variables
- clearer output
- additive machine-readable fields

Not allowed before a major release:

- removing or renaming commands, flags, or environment variables
- changing exit code meaning
- changing stdout or stderr contracts relied on by automation
- changing defaults in a way that alters existing invocation behavior

#### Configuration file and schema

Allowed in minor releases:

- new optional fields
- relaxed validation
- new accepted enum values
- additive schema metadata

Not allowed before a major release:

- removing or renaming fields
- changing field meaning
- changing serialized names
- making validation stricter for previously valid configs
- changing defaults so an unchanged config produces materially different behavior

#### Emitted telemetry

Allowed in minor releases:

- new spans
- new metrics
- new optional attributes
- additive semantic detail that does not break existing queries or time series identity

Not allowed before a major release:

- renaming or removing stable telemetry
- changing attribute keys
- changing metric units
- changing aggregation meaning incompatibly
- adding attributes in a way that unexpectedly breaks apart existing stable time series

#### Binaries and release artifacts

Allowed in minor releases:

- additional packaged artifacts
- additive metadata
- implementation changes that preserve invocation and packaging expectations

Never allowed:

- removing a published stable artifact
- changing archive layout incompatibly
- changing required runtime assumptions incompatibly
- making the same named artifact behave as a different product

#### Container images

Allowed in minor releases:

- base image refreshes
- security updates
- additive labels or metadata
- compatible startup improvements

Never allowed:

- changing entrypoint or command behavior incompatibly
- removing stable semver image tags; this does not apply to the moving `latest` tag, which is not stable and is not part of the compatibility contract
- changing image contents in ways that break documented usage for the same contract

#### Support matrix

Allowed in minor releases:

- adding support for new kernels, distros, runtimes, architectures, and instrumented libraries

Not allowed before a major release:

- removing previously supported environments from a stable support matrix, except where this policy explicitly carves out security or upstream end-of-life exceptions

#### Go version support for module consumers

Allowed in minor releases:

- adding support for newer Go versions
- dropping support for a Go minor version that is no longer supported by the Go project, provided maintainers give advance notice before the release that removes that support

Not allowed before a major release:

- dropping support for a Go version that is still supported by the Go project, unless that version was explicitly outside the OBI compatibility contract

## Special cases

The following areas require explicit care because users may otherwise assume stronger guarantees than OBI can realistically provide:

- eBPF and runtime coupling: kernel behavior, symbol layouts, JIT or runtime internals, and third-party library changes can affect instrumentation without any Go API change
- Go version support for module consumers is a build-time compatibility concern and is distinct from runtime support for the shipped binaries and container images
- support matrix changes: dropping an old kernel, distro, container runtime, language runtime, or library version may be a breaking change
- auto-instrumentation defaults: changing default enabled instrumentation, attribute sets, or span or metric naming can be breaking from the user's point of view
- generated configuration artifacts: changes to `docs/config-schema.json` and configuration validation are part of the public surface when configuration is stable
- image tags: `latest` is a moving, non-stable tag and is not part of the compatibility contract; the semver release tag is

## Deprecation

Once a surface is stable, deprecations MUST be documented before removal. Publicly stable artifacts and stable image tags MUST NOT be removed once published.
