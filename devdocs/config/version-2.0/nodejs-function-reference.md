# Node.js dynamic function references

← [Config v2 dynamic instrumentation](dynamic-instrumentation.md)

The Node.js dynamic-span selector matches a CommonJS exported function's full
symbol name: its module filename, followed by `:exports` and the exported
property path. For example:

```text
/app/checkout.js:exports.orders.placeOrder
```

Use glob patterns to leave details open and narrow the match only when needed:

```yaml
# Match this export from any file.
function: "**:exports.orders.placeOrder"

# If that matches too much, restrict it to checkout.js.
function: "**/checkout.js:exports.orders.placeOrder"
```

An absolute filename can select one exact discovered symbol. A bare function
name such as `placeOrder` does not match because selectors are matched against
the full symbol name. `*`, `?`, and `**` are supported; `*` and `?` match
characters including `/`, while `**` also matches across `/`. This is a
restricted glob syntax; character classes and brace alternatives are not
supported.

At injection, the agent discovers matching functions in already-loaded
file-backed CommonJS modules. It also examines modules loaded later. Discovery walks enumerable own data properties of exported objects and nested
functions to a bounded depth and count; getters are not invoked, and properties
that cannot be replaced are skipped. The final
property must hold a function. Matching references are wrapped so calls
through the exported property produce a span with the configured name.
Synchronous results, promise fulfillment, and thrown/rejected errors are
observed; errors are recorded and re-thrown. Constructor calls are also
wrapped. A reference copied from an export before injection cannot be
replaced, so calls through that earlier copy are not observed.

Built-in modules are not in `require.cache`; they can be targeted explicitly,
for example `node:fs:exports.existsSync`. Broad filename globs do not load
unrelated built-ins. ES modules, automatic attributes, explicit attributes,
`function_noret`, and USDT targets are not supported in this slice. A `nodejs`
language selector is optional and, when present, scopes the rule to matching
processes.

If an export cannot be inspected or wrapped, the rule is skipped without
blocking sibling rules. A per-rule warning with code
`OBI_DYNAMIC_SPAN_TARGET` identifies failures. Set
`OTEL_EBPF_NODEJS_DEBUG=1` in the target process to include details.
