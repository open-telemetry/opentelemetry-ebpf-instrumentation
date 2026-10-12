# Config v2 dynamic instrumentation

← [Config v2 reference](config-v2.md)

`capture.dynamic_instrumentation.rules` declares named spans for selected
services or workloads. Each rule has a `service` list using OBI's glob
discovery selectors and a `spans` list. Each span has a name and exactly one
target under `on`: `function`, `function_noret`, `usdt_span`, or `usdt_noret`.

## Function targets

`function` is a scalar string interpreted according to the selected service's
runtime. Native and Go targets use runtime symbol names or globs. Node.js
targets use exported CommonJS function names or globs when supported by a
runtime adapter. For example, a Node.js export is represented as
`/path/module.cjs:exports.method`; nested properties append `.name`. Java uses
the same `function` field with a source-style class and method reference:

| Reference form | Intended selection |
| --- | --- |
| `java.lang.StringBuffer#append(char)` | Exact overload |
| `java.lang.Runtime.Version#Version` | Unambiguous constructor |
| `java.lang.Runtime.Version#interim` | Callable selected by name when unambiguous |
| `com.example.Target#ready()` | Exactly zero arguments |
| `java.lang.StringBuffer#append(*)` | All overloads |

A Java reference without a parameter list is valid only when its callable name
is unambiguous; it does not assert zero arguments. Nested types use Java source
notation with dots (for example, `Runtime.Version`); a later runtime resolver
is responsible for resolving those to JVM binary names. This documents the
intended selection contract; it does not mean the schema or current runtime
resolves or instruments Java methods.

## Argument attributes

Optional `attributes` is a list mapping source arguments to span attribute
names. Each entry has a `name` and an `argument` with a zero-based `index` (0
through 11); `argument.type` optionally describes source decoding using `u8`,
`u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, or `string`. Omit the decoding
type only when runtime or probe metadata supplies it. The decoded value
determines the resulting OpenTelemetry attribute type; there is no separate
output-conversion setting. Named argument selection is deferred until runtime
support is demonstrated. `on.match` filters USDT events using its own
index/value argument form. Explicit attribute mappings are separate from
automatic function argument/result capture behavior; declaring mappings does
not disable that automatic capture.

This is currently declarative schema data only. Runtime integration is planned
for a later change; the v2 parser does not convert these entries into runtime
rules or apply them to running processes.

## Example

```yaml
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      dynamic_instrumentation:
        rules:
          - service:
              - languages: java
                k8s_namespace: shop
                k8s_deployment_name: search
            spans:
              - name: search
                # Choose exactly one target under on: function, function_noret, usdt_span, or usdt_noret.
                on:
                  function: "com.example.SearchService#search(java.lang.String,int)"
                attributes:
                  - name: search.query
                    argument: {index: 0, type: string}
                  - name: search.limit
                    argument: {index: 1, type: i32}
          - service:
              - languages: go
            spans:
              - name: checkout.place_order
                on:
                  function: "main.(*Checkout).PlaceOrder"
          - service:
              - languages: nodejs
            spans:
              - name: checkout.place_order
                on:
                  function: "/opt/checkout/handlers.cjs:exports.placeOrder"
```
