# OBI Configuration Principles

Status: Draft for discussion  
Audience: OBI maintainers and contributors  
Scope: principles for configuration model, schema, validation, and migration UX

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
