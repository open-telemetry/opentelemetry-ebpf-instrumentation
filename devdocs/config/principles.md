# OBI Configuration Principles

Status: Draft for discussion  
Audience: OBI maintainers and contributors  
Scope: principles and specification for configuration model, schema, validation, and migration UX

## Working Principles (used to derive the current design)

These are the design principles used in the current redesign work. They are intentionally user-centered and decision-oriented.

- **Journey-first, user-mental-model first**
  - Configuration should match what users are trying to do, not internal implementation layering.
  - Structure should optimize for readability and safe default operation.

- **One concern, one place**
  - Every concern has one canonical home.
  - Avoid parallel knobs for the same behavior across sections.

- **Top-level OTel is authoritative for pipeline semantics**
  - Exporters/processors/samplers belong to top-level declarative OTel sections.
  - OBI extension config should not reintroduce a competing pipeline model.

- **OBI-specific behavior lives under `extensions.obi`**
  - Runtime capture, selection, protocol controls, enrichment, and OBI limits are extension concerns.
  - OBI config should stay namespaced and composable.

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

## Specification

Normative terms in this section (MUST, SHOULD, MAY) are to be interpreted as described in RFC 2119.

- **Composable sections over mode-specific files**
  - Configuration MUST be organized into separable sections with clear ownership boundaries.
  - Users MUST NOT be required to encode runtime mode/topology in configuration files.

- **Host-owned applicability contract**
  - The runtime host (standalone OBI binary or Collector receiver integration) MUST provide the capability set used for applicability validation.
  - The same config file shape MUST be reusable across hosts; applicability is externally determined.

- **Single canonical key per concern**
  - Each concern MUST have exactly one canonical location in the target schema.
  - Legacy aliases MAY be accepted for migration only and MUST map deterministically with explicit warnings.

- **OTel declarative alignment first**
  - Export pipeline semantics MUST align with top-level OTel declarative configuration.
  - OBI-specific semantics MUST live in explicit extension space (`extensions.obi`) and MUST NOT sprawl as ad-hoc top-level keys.

- **Pipeline authority is top-level declarative config**
  - `tracer_provider` and `meter_provider` MUST be authoritative for processor/exporter pipeline definition.
  - `extensions.obi` MUST NOT define a parallel exporter pipeline in the target model.

- **Explicit versioning contract**
  - Declarative documents MUST declare root `version` for the OTel declarative contract.
  - OBI extension config SHOULD declare `extensions.obi.version` for extension contract selection.
  - Loaders MUST validate declarative contract first, then parse `extensions.obi` according to extension version.

- **Signal-scoped protocol controls**
  - Protocol enablement under `extensions.obi.instrumentation.<protocol>` MUST be signal-scoped.
  - Protocol and network filtering MUST be signal-scoped where filters are defined.

- **Validation prevents conflicts**
  - Invalid cross-section combinations MUST fail validation.
  - Implementations MUST NOT silently apply best-effort behavior for forbidden overlaps.

- **Source-of-truth schema + generated artifacts**
  - A single schema source MUST drive validation, documentation, snippets, and migration tooling.
  - Code structs SHOULD implement the schema contract and MUST NOT replace it as the external contract.

- **Migration as a product feature**
  - Breaking shape changes MUST include mapping rules, warning text, and an automated migration path.

- **Deterministic precedence and merge semantics**
  - Precedence across defaults, file values, env substitution, and runtime-injected values MUST be explicit, documented, and testable.
  - The same input MUST resolve to the same effective configuration.

- **Secure and safe-by-default behavior**
  - Unsafe/high-impact options MUST require explicit opt-in.
  - Ambiguous configurations SHOULD fail closed where they can cause incorrect exports or hidden data loss.

- **Explainability and debuggability**
  - Users MUST be able to inspect resolved configuration and value provenance.
  - Validation errors MUST include actionable remediation guidance.

- **Low cognitive load for common paths**
  - Common configuration paths SHOULD require minimal subsystem knowledge.
  - Advanced controls MUST remain available but SHOULD be isolated from default workflows.

- **Rename governance**
  - A key rename MUST be justified by a documented policy reason.
  - Renames MUST preserve naming consistency across the full configuration model.
  - Key names and syntax MUST be consistent with adjacent keys, section conventions, and OTel-aligned naming where applicable.
  - Allowed reasons are:
    - OTel declarative alignment,
    - canonical ownership placement,
    - naming consistency and syntax consistency,
    - unambiguous terminology improvement,
    - deprecation debt retirement.
  - Renames MUST NOT be introduced for stylistic preference alone.
