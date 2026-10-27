# Config v2 dynamic instrumentation

← [Config v2 reference](config-v2.md)

Dynamic span declarations are configured per capture rule under
`capture.rules[].refine.spans`. This keeps each declaration alongside the
workload selection it refines. A span has a name, exactly one target under
`on`, and optional `attributes` mappings. Supported target keys are
`function`, `function_noret`, `usdt`, and `usdt_noret`.

`function` and `function_noret` identify function targets; `usdt` and
`usdt_noret` identify USDT targets. The key selects the target family and
variant; target values must be non-empty strings. `function` is an opaque
runtime-specific reference. `function_noret` is a function symbol or glob for
an entry-only, zero-duration marker; its concrete symbol/glob syntax is defined
by each runtime adapter. `usdt` uses `provider:base` to identify paired
`<base>_start` and `<base>_end` probes. `usdt_noret` uses `provider:name` to
identify one zero-duration marker probe. `on.match` is valid only with a USDT
target and filters by equality against the selected string-valued argument.
Each runtime implementation must document its accepted function syntax and
unsupported target combinations before claiming support. Capture selectors
continue to use the semantics of the corresponding Config v2 selector; they
do not change the target-value syntax.

Each `attributes` entry names a span attribute and has an `argument` object.
`argument.index` selects the zero-based source argument (0 through 11), and
optional `argument.type` describes that same argument using an OBI-defined
decoding hint: `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, or
`string`. These hints are not language-specific types and do not configure the
output OpenTelemetry attribute type. The `automatic_attributes` boolean opts
into automatic argument/result capture; it defaults to `false`. When enabled,
explicit mappings take precedence over automatically captured attributes with
the same key; the automatic value is omitted. Spans may be declared only on
include rules; parsing rejects spans under exclude rules. Nested object
extraction is not supported by this configuration.

Malformed declarations are configuration errors. Runtime implementations must
evaluate each declaration independently: unresolved or ambiguous targets must
not select arbitrary candidates, and a failing rule must not prevent valid
siblings from applying. Each runtime documents resolution diagnostics and
attribute-collision behavior in its runtime reference.

The schema describes a shared contract, not support in every runtime. Each
runtime documents its accepted function syntax, target types, and attributes in
its runtime-specific reference. A converter accepts a declaration only when
that runtime can apply it; unsupported targets, attributes, and selector forms
must be rejected.

The following is an illustrative schema example; runtime acceptance depends
on the runtime-specific reference and tests.

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
              function: "com.example.Checkout#placeOrder"
            attributes:
              - name: order.id
                argument: {index: 0, type: string}
            automatic_attributes: false
```
