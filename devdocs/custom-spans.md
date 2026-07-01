# Custom Spans

Custom spans let you declare additional OpenTelemetry spans in OBI's
configuration, without modifying the application's source code or its
existing OpenTelemetry instrumentation. You name a span, point it at a
probe location (a USDT marker or a function symbol), and OBI attaches an
eBPF probe and emits matching OTLP spans from then on.

The feature is designed to surface application-defined events that
aren't captured by OBI's built-in protocol instrumentation — business
milestones, internal pipeline stages, vendored library calls, anything
you can identify by a probe point in the binary.

## When to use it

Reach for a custom span when you want to:

- **Surface a business event** the application already emits as a USDT
  probe (or could be patched to emit). Examples: an order moving to
  "paid", a feature flag flipping, a queue draining below a threshold.
- **Time an internal function** without touching the application code.
  Give OBI an ELF symbol; it emits a span around each call.
- **Filter a high-frequency probe down to one event of interest**. For
  example, Python's built-in `python:function__entry` fires for every
  function call. A custom span with a `match:` filter narrows it to a
  single function name in BPF, so userspace only ever sees the events
  you care about.

A custom span behaves like any other OpenTelemetry span: it carries a
name, a trace context (when one is available on the firing thread), and
a `map[string]string` of attributes pulled from the probe's arguments.

## Configuration at a glance

The feature activates automatically when at least one span is configured.

```yaml
ebpf:
  custom_spans:
    ttl: 1m        # how long to wait for an end event after a start
    spans:
      - name: order.process
        on:
          usdt_span: myapp:order
        attrs:
          order_id:
            arg: 0
          customer:
            arg: 1
            type: string

      - name: cache.hit
        on:
          usdt_noret: myapp:cache_hit
        attrs:
          key:
            arg: 0
            type: string

      - name: billing.charge
        on:
          function_span: billing::Service::charge
        attrs:
          tenant:
            arg: 0
            type: string
          request_id:
            arg: 2
            type: u64

      - name: py.process_paid_order
        on:
          usdt_noret: python:function__entry
          match:
            arg: 1
            value: process_paid_order
```

Each span needs a `name` and exactly one **target** under `on:`. There
are four target shapes:

| Target            | Meaning                                                     | Example                              |
| ----------------- | ----------------------------------------------------------- | ------------------------------------ |
| `usdt_noret`      | A one-off USDT marker. Emits a zero-duration span per fire. | A cache hit, a feature flag flip.    |
| `usdt_span`       | A pair of USDT markers `<base>_start` + `<base>_end`. Emits a span whose duration is the time between them. | The order lifecycle, a transaction. |
| `function_noret`  | An ELF symbol; one entry uprobe.                            | `init_complete` (never returns).     |
| `function_span`   | An ELF symbol; entry uprobe + uretprobe. Span = entry-to-return. | `billing::Service::charge`.      |

Optional modifiers:

- **`match:`** (any USDT shape) — drops events in BPF whose argument at
  `match.arg` doesn't equal `match.value` byte-for-byte. Useful for
  filtering broad probes like `python:function__entry` or
  `ruby:method__entry`.

For Go function-mode targets (`function_span:` / `function_noret:`) OBI
also auto-extracts every primitive argument from the target method's
runtime type metadata — no `attrs:` block needed. See
[Automatic argument extraction](#automatic-argument-extraction-go-function-mode).

### `attrs`

`attrs` is a map from the attribute name (as it will appear on the OTLP
span) to the probe argument and how to read it.

```yaml
attrs:
  order_id: # integer, sign+width auto-derived from ELF (USDT only)
    arg: 0
  customer: # always specify `type: string` for strings
    arg: 1
    type: string
  status: # explicit integer type (required for function-mode)
    arg: 2
    type: i32
```

String attributes are read up to 128 bytes per fire.

### Automatic argument extraction (Go function-mode)

For `function_span:` and `function_noret:` targets on Go binaries, OBI
automatically discovers and extracts every primitive scalar and string
argument of the target method — no `attrs:` block needed. Works on
stripped binaries (`-ldflags="-s -w"`, no DWARF, no `.symtab`) by walking
the runtime type tables (`.typelink` → `_type` → `funcType`) the Go
linker keeps for the runtime's own reflect support.

```yaml
- name: order.place
  on:
    function_span: "main.(*Order).Place"
```

That's it. No `attrs:` block needed for the common case.

At attach time OBI resolves the receiver type, decodes the method's
signature, and emits one BPF spec entry per primitive argument. The
emitted span carries:

- `arg0`, `arg1`, … for top-level scalar and string args
- `argN.<FieldName>` for primitive fields reachable through a struct-
  pointer arg (Go's idiomatic `*Request` handler pattern)

#### What you get

Any scalar or string argument the compiler passes in a register:
booleans, signed and unsigned integers up to 8 bytes, `uintptr`, and
`unsafe.Pointer` values. Go strings (a `{data, len}` pair) are captured
as-is. And, importantly, if an argument is a pointer to a struct, every
scalar or string field of that struct is captured too — the common
`Handler(ctx, *Request)` shape emits one attribute per field of
`Request`.

#### What you don't get (yet)

A few argument shapes are ignored today. Timing still works — the
probe attaches, the span fires, its duration is correct — but no
attribute is emitted for the argument.

- **Slices, maps, channels, interfaces, function values.** They occupy
  the right number of registers for correctness, but nothing is
  extracted from them.
- **Nested pointers inside a struct.** If `*Request` contains
  `Address *Address`, fields of `Address` don't appear on the span —
  only one level of indirection is followed.
- **Floats.** Go passes them in FPU registers, which don't ride along
  in the `pt_regs` snapshot uprobes receive.
- **Long argument lists.** After nine integer arguments on amd64
  (sixteen on arm64) Go spills to the stack; extraction stops at that
  boundary.
- **Unexported struct fields.** Most are codegen internals
  (`sizeCache`, `state`, `unknownFields` on protobuf types) and would
  clutter every span.
- **Value-receiver methods and plain top-level functions.** Only the
  `pkg.(*Type).Method` symbol form is decoded; other shapes still
  attach the probe but skip auto extraction.
- **Methods on types not reached via reflection.** The Go linker drops
  the method's signature metadata if nothing in the program calls
  `reflect.TypeOf(...)` (or an equivalent) on the receiver. The probe
  still attaches, the span still fires, only the auto-extracted
  attributes are missing. A debug log line records the reason.

The roadmap for closing these gaps is in [TODO](#todo).

#### Adding a manual `attrs:` on top

You can always write an `attrs:` block alongside auto extraction, and
your entries win. If you point a manual attribute at an argument the
auto pass already covers, your name and type replace the auto slot;
otherwise the two lists are simply merged on the span.

Reasons to reach for this:

- renaming a noisy field name (`arg1.UserId` → `user_id`);
- overriding an inferred type (asking for `u64` where the auto pass
  guessed `i64`);
- extracting something the auto pass couldn't see — for example a
  register-level value on a non-Go binary.

On non-Go binaries the auto pass is a no-op. Only your `attrs:` block
runs, and the probe still attaches so you at least get the timing span.

### `ttl`

`ttl` controls how long the pairer holds a start event while waiting for
its matching end. If the end never arrives, the start is dropped after
`ttl` and no span is emitted.

Pick a value comfortably above your longest expected span duration. The
default is 5 minutes.

## Language support

Custom spans don't care which language emitted the probe — they only
care about probe identity in the target binary. The matrix below shows
which OBI features each language can drive in practice, and the
instrumentation library or technique that gets you there.

| Language | `usdt_noret` / `usdt_span` | `function_noret` / `function_span` | `match:` modifier | How to emit USDT from this language                                                                       |
| -------- | -------------------------- | ---------------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------- |
| C / C++  | ✅                          | ✅                                  | ✅                 | `<sys/sdt.h>` `DTRACE_PROBE*`, or facebook/folly `FOLLY_SDT` (always-fires) / `FOLLY_SDT_WITH_SEMAPHORE`. |
| Rust     | ✅                          | ✅                                  | ✅                 | `libstapsdt-rs` / `sdt-rs`.                                                                               |
| Go       | ✅                          | ✅ (function_span attaches per-RET uprobes; kernel uretprobe is unsafe on Go because the trampoline rewrites the on-stack return address) | ✅                 | [`mmcshane/salp`](https://github.com/mmcshane/salp) registers probes at runtime. |
| Python   | ✅                          | ❌ (no static symbols)              | ✅                 | `python-stapsdt`; builtin `python:function__entry` is present in distro CPython 3.11 but does not fire on the specialized-interpreter hot path. |
| Ruby     | ✅                          | ❌                                  | ✅                 | `ruby-stapsdt`.                                                                                           |
| Java     | ✅                          | ❌                                  | ✅                 | Small JNI bridge over libstapsdt (the integration test ships one). HotSpot's built-in `hotspot:method__entry` requires a JDK built with full DTrace support — distro and Temurin builds don't qualify. |
| Node.js  | ✅                          | ❌                                  | ✅                 | Node-API addon over libstapsdt (the integration test ships one). The upstream `dtrace-provider` works on x86_64 but not on arm64. |

For function-mode spans, OBI auto-detects whether the binary is Go (via
`.gopclntab` and friends) or C/C++ and reads string arguments with the
matching calling convention. The Go-string read uses the regabi-emitted
`{ptr, len}` pair from non-consecutive registers on amd64 (AX/BX/CX/DI/SI/R8/…),
not a `reg_off+8` adjacency assumption.

Go binaries stripped with `-ldflags="-s -w"` keep `.gopclntab`. OBI
resolves `function_span: "main.Foo"` against it when `.symtab` is empty,
so production-built Go services work zero-code.

The `match:` modifier needs `bpf_get_attach_cookie()` (kernel ≥5.15) to
disambiguate two `custom_spans` that share a probe IP. On older kernels
OBI silently skips the `match:`-filtered span and keeps the unfiltered
base attached.

### Quick recipes per language

Each block below shows the application-side probe declaration paired
with the matching `custom_spans:` entry. For languages that support both
USDT and function-mode probes, both variants are shown.

#### C / C++

USDT paired (via `<sys/sdt.h>`):

```c
#include <sys/sdt.h>

void process_order(uint64_t order_id, const char *customer) {
    DTRACE_PROBE2(checkout, order_start, order_id, customer);
    do_work();
    int32_t status = 0;
    DTRACE_PROBE2(checkout, order_end, order_id, status);
}
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

USDT paired with folly (semaphore-gated; skipped when no eBPF consumer):

```cpp
#include <folly/tracing/StaticTracepoint.h>

FOLLY_SDT_DEFINE_SEMAPHORE(checkout, order_start)
FOLLY_SDT_DEFINE_SEMAPHORE(checkout, order_end)

void process_order(uint64_t order_id, const char *customer) {
    FOLLY_SDT_WITH_SEMAPHORE(checkout, order_start, order_id, customer);
    do_work();
    int32_t status = 0;
    FOLLY_SDT_WITH_SEMAPHORE(checkout, order_end, order_id, status);
}
```

Function-mode paired (no source change needed; `__attribute__((noinline))`
keeps the symbol alive under `-O2`):

```c
__attribute__((noinline)) void process_order(uint64_t order_id,
                                             const char *customer) {
    // existing implementation
}
```

```yaml
- name: order.func
  on:
    function_span: process_order
  attrs:
    order_id:
      arg: 0
      type: u64
    customer: # C ABI: arg 1 = RSI / x1
      arg: 1
      type: string
```

#### Rust — via the [`usdt`](https://crates.io/crates/usdt) crate

USDT paired:

```rust
#[usdt::provider(provider = "checkout")]
mod probes {
    fn order_start(_id: u64, _customer: &str) {}
    fn order_end(_id: u64, _status: i32) {}
}

fn process_order(id: u64, customer: &str) {
    probes::order_start!(|| (id, customer));
    do_work();
    probes::order_end!(|| (id, 0_i32));
}
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

Function-mode paired (Rust auto-detected from ELF; uses Go-style
`{ptr,len}` because Rust `&str` shares that representation):

```rust
#[no_mangle]
#[inline(never)]
pub fn process_order(id: u64, customer: &str) {
    // `no_mangle` keeps the symbol queryable as plain `process_order`;
    // `inline(never)` keeps a callable body addressable.
}
```

```yaml
- name: order.func
  on:
    function_span: process_order
  attrs:
    order_id:
      arg: 0
      type: u64
    customer:
      arg: 1
      type: string
```

#### Go — via [`mmcshane/salp`](https://github.com/mmcshane/salp)

USDT paired:

```go
provider := salp.NewProvider("checkout")
orderStart := salp.MustAddProbe(provider, "order_start", salp.Uint64, salp.String)
orderEnd   := salp.MustAddProbe(provider, "order_end",   salp.Uint64, salp.Int32)
_ = provider.Load()

func processOrder(id uint64, customer string) {
    orderStart.Fire(id, customer)
    time.Sleep(20 * time.Millisecond)
    orderEnd.Fire(id, int32(0))
}
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

Function-mode paired (note the `//go:noinline` directive so the symbol
survives the inliner):

```go
//go:noinline
func processOrder(id uint64, customer string) {
    // ...
}
```

```yaml
- name: order.func
  on:
    function_span: main.processOrder
  attrs:
    order_id: # Go regabi: x0 / AX
      arg: 0
      type: u64
    customer: # {ptr, len} in x1+x2 / BX+CX
      arg: 1
      type: string
```

#### Python — via [`python-stapsdt`](https://pypi.org/project/stapsdt/)

USDT paired:

```python
import stapsdt

provider = stapsdt.Provider("checkout")
order_start = provider.add_probe("order_start", stapsdt.ArgTypes.uint64, stapsdt.ArgTypes.uint64)
order_end   = provider.add_probe("order_end",   stapsdt.ArgTypes.uint64, stapsdt.ArgTypes.int32)
provider.load()

def process_order(order_id, customer):
    buf = ctypes.create_string_buffer(customer.encode("ascii"))
    order_start.fire(order_id, ctypes.c_void_p(ctypes.addressof(buf)))
    do_work()
    order_end.fire(order_id, 0)
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

`match:` on the builtin `python:function__entry` — no extra
instrumentation needed in the application; CPython itself fires the
probe on every interpreted function call, and OBI drops every event in
BPF except the one whose function name matches:

```python
# requires CPython built with --enable-pydtrace
def process_paid_order(order_id: int, customer: str) -> None:
    settle_payment(order_id)
    notify(customer)
```

```yaml
- name: py.process_paid_order
  on:
    usdt_noret: python:function__entry
    match:
      arg: 1
      value: process_paid_order
```

#### Ruby — via [`ruby-stapsdt`](https://github.com/rock-core/ruby-stapsdt)

USDT paired:

```ruby
require "stapsdt"

provider = Stapsdt::Provider.new("checkout")
order_start = provider.add_probe("order_start", :uint64, :uint64)
order_end   = provider.add_probe("order_end",   :uint64, :int32)
provider.load

def process_order(order_id, customer)
  order_start.fire(order_id, customer)
  sleep 0.020
  order_end.fire(order_id, 0)
end
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

#### Java — JNI bridge over libstapsdt

The integration test ships a minimal `Stapsdt.java` + `jstapsdt.c` you
can vendor; the public API matches the python/ruby pattern:

```java
long provider    = Stapsdt.providerInit("checkout");
long orderStart  = Stapsdt.addProbeU64U64(provider, "order_start");
long orderEnd    = Stapsdt.addProbeU64I32(provider, "order_end");
Stapsdt.providerLoad(provider);

void processOrder(long orderId, String customer) {
    Stapsdt.fireU64Str(orderStart, orderId, customer.getBytes(UTF_8));
    Thread.sleep(20);
    Stapsdt.fireU64I32(orderEnd, orderId, 0);
}
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

#### Node.js — Node-API addon over libstapsdt

Mirrors the integration test's `binding.cc` + `binding.gyp`:

```javascript
const stapsdt   = require('./build/Release/node_stapsdt.node');
const provider  = stapsdt.providerInit('checkout');
const orderStart = stapsdt.addProbeU64U64(provider, 'order_start');
const orderEnd   = stapsdt.addProbeU64I32(provider, 'order_end');
stapsdt.providerLoad(provider);

function processOrder(orderId, customer) {
    stapsdt.fireU64Str(orderStart, orderId, customer);
    // ... do work ...
    stapsdt.fireU64I32(orderEnd, orderId, 0);
}
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

### Attribute and matching cheat sheet

- **Integer attribute (USDT)** — `arg: N` is enough; OBI derives sign +
  width from the `.note.stapsdt` record.
- **Integer attribute (function-mode)** — explicit `type:` is required
  (`u8` / `u16` / `u32` / `u64` / `i8` / `i16` / `i32` / `i64`); OBI
  reads the register at the given index.
- **String attribute** — `type: string` always required; OBI reads up to
  128 bytes per fire.
- **`match:` filter** — drop events whose arg at `match.arg` doesn't
  byte-equal `match.value` (max 63 bytes). Valid on any USDT shape;
  not allowed on function-mode (use a more specific symbol instead).

## Examples

### Order-processing pipeline (paired + single + match)

A C service emits stapsdt probes for the order lifecycle plus a higher-
frequency `cache_hit` event. We also surface Redis `GET` calls without
attaching to every command:

```yaml
ebpf:
  custom_spans:
    ttl: 1m
    spans:
      - name: order.process
        on:
          usdt_span: checkout:order
        attrs:
          order_id:
            arg: 0
          customer:
            arg: 1
            type: string

      - name: cache.hit
        on:
          usdt_noret: checkout:cache_hit
        attrs:
          key:
            arg: 0
            type: string

      - name: redis.get
        on:
          usdt_noret: checkout:redis_cmd
          match:
            arg: 0
            value: GET
        attrs:
          key:
            arg: 1
            type: string
```

### Time a Go function without source changes

```yaml
- name: billing.charge
  on:
    function_span: billing.(*Service).Charge
  attrs:
    tenant:
      arg: 0
      type: string
    request_id:
      arg: 2
      type: u64
```

OBI detects Go from the binary's ELF, reads `tenant` as a Go `{ptr, len}`
string, and emits a span whose duration is the entry-to-return time.

The same target without a manual `attrs:` block:

```yaml
- name: billing.charge
  on:
    function_span: billing.(*Service).Charge
```

attaches the same probe, emits the same span shape, and additionally
populates `arg0`, `arg1`, … (plus `arg2.Field` for any `*Request`-style
argument) from the receiver type's runtime metadata at attach time. No
DWARF required; works on stripped binaries.

### Surface a specific Python function

```yaml
- name: py.process_paid_order
  on:
    usdt_noret: python:function__entry
    match:
      arg: 1
      value: process_paid_order
```

One uprobe attached to the high-frequency `python:function__entry`
probe, but events are discarded in BPF unless the function name matches
exactly. Requires Python built with `--enable-pydtrace`.

## Known limitations

- **`function_span` correlates entry and return on the firing thread.**
  A recursive call on the same thread overwrites the pending start, so
  only the innermost iteration of a recursion is captured.
- **`match:` on `usdt_span`.** Both the start and end probes share the
  same filter spec. If your start and end carry different values at the
  match index, one side will be dropped and the span won't pair.
- **`hotspot:method__entry`.** OpenJDK's built-in method-entry USDT
  requires a JDK built with full DTrace USDT support. Stock Temurin /
  distro OpenJDK doesn't ship that — use the JNI-via-libstapsdt
  pattern instead (see the integration test sample).
- **Verifier-rejected configurations.** Match values longer than 63
  bytes are rejected at validation. The same applies to spans that
  reference more than 12 probe arguments.
- **Auto attribute extraction on Go binaries** covers only the
  `pkg.(*Type).Method` symbol form. Value-receiver methods, plain
  top-level functions, and methods on types not reached via
  `reflect.TypeOf` degrade to a timing-only span (auto attrs are
  dropped, `attrs:` still runs).

## TODO

A running list of gaps and known future work.

### Better symbol resolution for `function_span`

Today `function_span: "process_order"` matches the ELF symbol table
exactly. That works well for C and Go, but Rust callers have to opt
into `#[no_mangle]` and C++ callers have to paste the full Itanium
mangled name. Hooking
[`ianlancetaylor/demangle`](https://pkg.go.dev/github.com/ianlancetaylor/demangle)
into the symbol lookup path would let people write natural-looking
targets — `billing::Service::charge`, `process_order` — regardless of
which language emitted the binary.

### Better integration coverage for two builtin probes

`hotspot:method__entry` and `python:function__entry` are documented as
supported, but neither is exercised end-to-end in CI.

The HotSpot probe note ships in `libjvm.so`, yet the call sites are
stripped from release JDK builds — `DTraceMethodProbes` is a `develop`
flag. Real coverage would need a fastdebug JDK build or a distribution
that ships full DTrace USDT support. The integration test uses a
JNI-over-libstapsdt bridge for now, which works but doesn't exercise
the builtin probe.

The Python builtin is a similar story. Distro CPython 3.11 reports
`WITH_DTRACE=1` and ships `.note.stapsdt` entries, but the probe call
sites in `libpython3.11.so` never fire in practice — a `bpftrace`
against a tight `def` loop yields zero events. The most likely cause
is the 3.11+ specialized adaptive interpreter bypassing the probe on
the hot path. Getting this to work in CI needs either a CPython build
that keeps the slow path alive or a custom build that pins the probe
call site. Today the `match:` path is exercised via an application-
emitted `custom_span_py:cache_hit` probe instead.

### Recursive `function_span` correlation

The pairer keys on the firing thread's TID (C) or goroutine pointer
(Go). A recursive call on the same thread or goroutine overwrites the
pending start, so only the innermost iteration produces a span. A
bounded stack of pending starts per key would let us recover the outer
span too, at some memory cost.

### Slimmer cross-tracer attach

When `custom_spans` is configured on a Go binary, the finder currently
piggybacks a full `generictracer` on the process. That pulls in the
whole generictracer kprobe set (HTTP, gRPC, SQL, …) even when the user
only asked for custom spans. Lifting the custom-span attach path into
its own tiny sub-tracer would remove the overlap.

### Widening Go auto attribute extraction

The auto pass covers registers, Go strings, and one level of
struct-pointer indirection. Everything else in
[What you don't get (yet)](#what-you-dont-get-yet) is silently skipped.
Roughly in order of impact:

#### Making slices, maps and interfaces useful

Today a `[]Item` or `map[string]User` or `context.Context` argument
consumes register slots for correctness and emits nothing. Each has an
easy fix using the extraction machinery that already exists.

- A **slice header** occupies three consecutive registers (data, len,
  cap). Emitting the length as `argN.len` is a one-line addition to
  the recipe builder — no BPF changes.
- A **map** is passed as a pointer to the runtime's `hmap`, whose
  first field is the entry count. Reading it via the existing
  pointer-field-scalar encoding gives a free `argN.len`.
- An **interface** is a `{itab, data}` pair. Emitting the data pointer
  as an opaque `uintptr` tells the user "the value was non-nil". A
  later refinement can look through the itab of common interface
  types (starting with `context.Context`) and expose the concrete
  value.

Together these turn three of the largest silent-skip categories into
useful attributes without touching BPF.

#### Reaching deeper into request objects

Real gRPC handlers often look like `Handler(ctx, *Request)` where
`Request` holds `Address *Address` or `User *UserProfile`. The auto
pass currently walks one level into `*Request` but stops at the
nested pointer. Following the chain would cover the pattern that
dominates production traces.

The cleanest shape is a new BPF argument type that carries a small
list of dereference offsets — two or three hops is enough for almost
every real case. Each hop reads a pointer, adds the next offset, and
so on. The verifier is comfortable with a fixed unrolled chain,
including on the older kernel where the 1M-instruction ceiling
applies.

Along with this it makes sense to add a per-span opt-in for keeping
unexported fields, for the rare user who actually wants proto
internals like `sizeCache`.

#### The linker-dropped-metadata problem

Go's linker strips a method's signature from the runtime type table
when nothing in the program reaches the receiver via reflection. In
the OpenTelemetry demo checkout this is what silently hid
`chargeCard`, `shipOrder`, `sendOrderConfirmation`, and
`prepOrderItems`: OBI attached the probes and the spans fired, but no
attributes came out.

The fix is DWARF. Go keeps DWARF by default; only aggressive
`-ldflags="-w"` strips it. When the runtime type table doesn't have
what we need, walking `.debug_info` for the target symbol recovers
the full signature, including all the fields inside its parameter
structs. The same fallback code trivially unlocks C, C++, and Rust
binaries built with debug information.

This is the single largest improvement on the list: it eliminates the
whole "methods on non-reflected types" and "plain top-level functions"
categories in one step.

#### Long argument lists and slice contents

Once the register pool is exhausted (nine integer arguments on amd64,
sixteen on arm64) Go spills the rest to the caller's frame. The layout
is fully deterministic from the function's signature, so extraction
can continue from `sp+offset` for anyone who really has functions with
that many parameters — mostly generated code, batch handlers, and
some protobuf-heavy paths.

A related refinement is reading the first few elements of a slice
argument. Given the slice's data pointer and length, the BPF program
can loop up to a fixed cap (eight elements is verifier-friendly) and
emit `argN.0`, `argN.1`, and so on. This is the difference between
"there was a batch of 42 orders" and "the first eight order IDs were
X, Y, Z…". Scalar and string element types cover most useful cases.
