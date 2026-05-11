# Attribute Selection

## Trace selection (`traces`)

For exported OpenTelemetry traces, use the `traces` key (not a metric name) under
`attributes.select`. It controls optional trace decoration such as `db.query.text`,
`url.query`, GenAI payload attributes, and **`db.response.error`**.

## `db.response.error`

`db.response.error` is **not** part of the OpenTelemetry semantic conventions.
OBI reuses that string only as a **configuration flag** under
`attributes.select.traces`.

- **Default (not included):** On failed database-related spans (for example SQL,
  Redis, MongoDB, Couchbase, Memcached, or SQL++ over HTTP),
  `span.status.message` is left **empty**. This is consistent with how other
  optional attributes (e.g. `db.query.text`) behave — when not selected, they are
  simply omitted.
- **When included:** On those same spans, `span.status.message` is set to the
  **actual** error description parsed from the protocol response.
- **Exported attributes:** `db.response.error` is **never** attached as a span
  attribute on OTLP traces. During export, OBI uses the gated value only to build
  `span.status.message` for database spans, then drops the attribute from the
  exported span. Enabling this option changes **status description**, not a
  separate `db.response.error` field on the span.

Opt-in exists because error strings may contain sensitive or high-cardinality
detail (schema names, fragments of queries, or data values).

### Example

```yaml
attributes:
  select:
    traces:
      include:
        - db.response.error
```
