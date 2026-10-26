# Node.js dynamic function references

← [Config v2 dynamic instrumentation](dynamic-instrumentation.md)

The current Node.js dynamic-span slice supports exact CommonJS exported
functions. Its `on.function` target uses this form:

```text
moduleSpecifier#exportPath
```

`moduleSpecifier` is an exact specifier accepted by Node.js CommonJS
`require()`, such as `@example/checkout`, `./checkout.js`, or an absolute file
path; glob metacharacters are not supported. `exportPath` is one or more
dot-separated ASCII JavaScript identifiers naming an exported function or
nested exported function. Each identifier starts with an ASCII letter, `_`, or
`$`, and may then contain ASCII letters, digits, `_`, or `$`. For example:

```yaml
capture:
  rules:
    - action: include
      match:
        process:
          language_glob: [nodejs]
          cmd_args_glob: ["node app.js"]
      refine:
        spans:
          - name: checkout.place_order
            on:
              function: "./checkout.js#orders.placeOrder"
```

The specifier is resolved with Node.js's CommonJS resolver in the loading
module's context. A matching exported property is instrumented if its module is
already loaded when injection occurs or is loaded later. The export path must
contain own data properties, and its final value must be a function. Calls
produce a span with the configured name; synchronous results, promise
fulfillment, and thrown/rejected errors are observed. Errors are recorded and
re-thrown to the application. Calling an exported function as a constructor
does not produce a span.

This slice does not support globs, ES modules, automatic attributes, explicit
attributes, `function_noret`, or USDT targets. The converter accepts span rules
only when the rule explicitly selects `process.language_glob: [nodejs]` and the
span has no attribute mappings. A function reference copied from an export
before injection cannot be replaced; use the exported property after injection
for calls to be observed. Other runtime declarations remain rejected.

If a configured module is loaded but its export path is absent, is not a
function, or cannot be inspected, the rule is skipped without blocking sibling
rules. A per-rule warning with code `OBI_DYNAMIC_SPAN_TARGET` identifies the
rule once. Set `OTEL_EBPF_NODEJS_DEBUG=1` in the target process to include
resolution details.
