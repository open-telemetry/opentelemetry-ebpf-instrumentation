# Config v2 dynamic instrumentation

← [Config v2 reference](config-v2.md)

Dynamic span declarations are configured per capture rule under
`capture.rules[].refine.spans`. This keeps each declaration alongside the
workload selection it refines. A span has a name, exactly one target under
`on`, and optional `attributes` mappings. Supported target keys are
`function_span`, `function_noret`, `usdt_span`, and `usdt_noret`.

`function_span` and `function_noret` identify function targets. The function
reference is an opaque string interpreted by a future runtime-specific
adapter; this schema does not define or guarantee a Java, Go, Node.js, or native
reference syntax. USDT targets identify probes, and `on.match` can filter USDT
events by an argument index and string value.

Each `attributes` entry names a span attribute and has an `argument` object.
`argument.index` selects the zero-based source argument (0 through 11), and
optional `argument.type` describes that same argument using an OBI-defined
decoding hint: `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, or
`string`. These hints are not language-specific types and do not configure the
output OpenTelemetry attribute type. The `automatic_attributes` boolean opts
into automatic argument/result capture;
it defaults to `false`. Explicit `attributes` mappings coexist with and add to
automatically captured attributes when the option is `true`. If both sources
produce the same attribute name, collision behavior is not defined yet and
awaits runtime support. Spans may be declared only on include rules; parsing
rejects spans under exclude rules. Nested object extraction is not supported
by this configuration.

This is configuration schema only. The runtime converter rejects non-empty
dynamic span declarations rather than accepting configuration that it cannot
apply. No runtime instrumentation is promised by this configuration.

```yaml
capture:
  rules:
    - name: checkout
      action: include
      match:
        process:
          language_glob: [java]
      refine:
        spans:
          - name: checkout.place_order
            on:
              function_span: "com.example.Checkout#placeOrder"
            attributes:
              - name: order.id
                argument: {index: 0, type: string}
            automatic_attributes: false
```
