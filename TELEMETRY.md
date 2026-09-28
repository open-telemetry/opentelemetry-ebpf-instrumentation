# OBI telemetry compatibility contract

Starting with OBI v1.0, this document defines the compatibility contract for
telemetry OBI emits. [VERSIONING.md](./VERSIONING.md) defines how changes to
that contract affect release versions.

## Contract surface

The resolved semantic-convention registry for a release is the source of truth
for its telemetry surface. It combines OBI's registry under
[`schemas/obi/`](./schemas/obi/) with the pinned upstream OpenTelemetry
semantic conventions. The [generated telemetry reference](./site/docs/README.md)
renders that resolved registry for people to read.

The stable v1 surface is the closed set of registry entries classified as
`stable` in the v1.0 release. A later minor release may add stable telemetry,
but it must preserve the stable entries from earlier v1 releases according to
[the emitted-telemetry versioning rules](./VERSIONING.md#emitted-telemetry).
Telemetry that OBI emits but the resolved registry does not document as stable
is not part of the v1 compatibility contract.

## Stability classifications

Only entries classified as `stable` are protected by the v1 compatibility
policy.

| Registry status | v1 compatibility guarantee |
| --- | --- |
| `stable` | Protected by the compatibility and release rules in `VERSIONING.md`. |
| `development` (default), `alpha`, `beta`, or `release_candidate` | Not protected; the entry may change or be removed in a v1 minor release. |
| `deprecated` | Protection follows the entry's stability classification. A deprecated stable entry remains protected; other deprecated entries are not protected. |

"Experimental" is older terminology for development telemetry and does not
create a separate protected class.

Signal and attribute classifications apply independently. A stable signal may
contain attributes with lower stability; those attributes are not protected.
Likewise, a stable attribute used by a development signal does not make that
signal stable. Attribute groups organize definitions and are not emitted
signals themselves.

For stable entries, the contract protects the identifiers and semantics needed
to consume the telemetry. These include metric names, instrument kinds, units,
and aggregation meaning; span naming rules and kinds; and attribute keys,
types, and meaning. Compatible additions described in `VERSIONING.md`, such as
new signals or optional attributes, may be made in minor releases.

## Exporters

The contract covers both OTLP telemetry and metrics produced by OBI's built-in
Prometheus exporter.

- OTLP uses the metric and attribute identifiers shown in the generated
  reference.
- Prometheus metric names are derived with the upstream Prometheus OTLP
  translator used by the OpenTelemetry Collector. Attribute keys are converted
  to their corresponding Prometheus label names. The translated representation
  of a stable registry entry is protected along with the OTLP representation.
- Spans have no Prometheus representation, so their contract applies only to
  OTLP.

The published OpenTelemetry schema files and the `schema_url` attached to
telemetry describe OTLP transformations. The schema format cannot express
Prometheus-specific changes, but that limitation does not remove Prometheus
output from this compatibility contract.

## Exclusions and caveats

### Known v1 emission limitations

These limitations apply when the related telemetry is enabled. Listing a
development signal here does not make it part of the stable v1 surface.

- Service graph metrics from the built-in Prometheus exporter do not include a
  unique OBI-instance label. Preserve the Prometheus target `instance` label, or
  an equivalent external label, when combining series from multiple OBI scrape
  targets.
- Port-based process discovery can select a host-side helper or port-forwarder
  that binds the same published port as a container workload. Telemetry from
  the helper can then carry the workload's service identity. Use an
  executable-path, container, or Kubernetes selector when multiple processes
  expose that port.
- Service graph destination names can be `outgoing` when a Kubernetes Service
  resolves to a Pod IP that is not available in the informer cache. Non-HTTP
  destinations have the same fallback when Kubernetes metadata is unavailable;
  reverse-DNS resolution is optional and disabled by default.
- When OBI resolves a destination as a Kubernetes Service rather than a Pod, it
  cannot map the Service selector back to a Pod's OpenTelemetry service-name or
  namespace overrides. The service graph can therefore contain separate nodes
  using the Kubernetes and OpenTelemetry identities.
- After a Kubernetes Pod starts or restarts, its application metrics can
  intermittently remain absent until OBI restarts. A failed initial
  PID-to-container lookup is suspected, but the cause has not been confirmed.
- Child spans can intermittently have start timestamps earlier than their
  parents, including for same-node traces. The cause is not yet known.

### Compatibility caveats

- A stable classification describes the shape and meaning of telemetry when it
  is emitted. It does not make emission unconditional. Enabled features,
  instrumented protocols, attribute selection, declared requirement levels,
  and the metadata available at runtime still determine which telemetry and
  attributes appear.
- Telemetry from deprecated features remains outside the contract unless its
  registry entry is independently classified as stable.
- Correctness fixes that make emitted telemetry conform to its documented
  semantics are compatible changes. The contract does not preserve bugs,
  undocumented values, or accidental emission behavior.
