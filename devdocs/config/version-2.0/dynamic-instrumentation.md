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

Malformed declarations are configuration errors. Each runtime evaluates
declarations independently: a failing rule must not prevent valid sibling
rules from applying, and an ambiguous target must not select an arbitrary
candidate. For the supported Node.js subset, a resolved module with a missing,
non-function, or uninspectable export emits a per-rule warning and does not
block valid siblings. Resolution diagnostics for module specifiers that never
resolve, and attribute-collision behavior, remain to be specified or hardened
as additional runtime support is added.

The runtime converter currently accepts only the Node.js subset documented in
the [Node.js function-reference contract](nodejs-function-reference.md): exact
CommonJS module exports, no attributes, and rules explicitly selecting
`nodejs`. Java, Go, native, other runtimes, and unsupported Node.js target forms
remain rejected until implemented. The [Java selector contract](java-method-reference.md)
defines Java syntax but does not imply Java runtime support.

The shared schema also permits explicit source-argument mappings. This Java
example documents the contract only; the current converter rejects it because
Java runtime span support and attribute capture are not implemented:

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
```

The following exact CommonJS rule is accepted by the current Node.js runtime
slice:

```yaml
capture:
  rules:
    - name: checkout
      action: include
      match:
        process:
          language_glob: [nodejs]
      refine:
        spans:
          - name: checkout.place_order
            on:
              function: "./checkout.js#placeOrder"
```
