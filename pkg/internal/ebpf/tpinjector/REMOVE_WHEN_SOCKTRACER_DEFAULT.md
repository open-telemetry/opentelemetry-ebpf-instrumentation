# tpinjector removal plan

tpinjector is a backward-compatibility shim. It was the original context-propagation
mechanism (sk_msg + sockops) before socktracer existed. It is kept alive so that users
who set `context_propagation: all` (or any non-disabled value) without enabling
`socket_tracer: true` do not silently lose header/TCP-option injection.

Once socktracer is enabled by default (or `context_propagation` is defined to imply
`socket_tracer`), tpinjector must be deleted. This file is the authoritative checklist
for that removal.

---

## Trigger condition

Remove tpinjector when **both** of the following are true:

1. `socket_tracer: true` is the default (or `context_propagation != disabled`
   automatically enables socktracer without requiring an explicit opt-in).
2. Any deprecation/migration notice for `context_propagation`-without-`socket_tracer`
   has been communicated to users for at least one release cycle.

---

## Files to delete entirely

| Path | Why |
|---|---|
| `pkg/internal/ebpf/tpinjector/` | The entire Go package (this file included) |
| `bpf/tpinjector/tpinjector.c` | BPF sk_msg + sockops injection program |
| `bpf/tpinjector/sock_iter.c` | BPF iter/tcp for existing-connection backfill |
| `bpf/tpinjector/maps/sk_tp_info_pid_map.h` | tpinjector-local SK_STORAGE map |
| `bpf/common/msg_buffer.h` | Shared buffer type used only by tpinjector↔kprobe bridge |
| `bpf/maps/msg_buffers.h` | Pinned LRU map used only by tpinjector↔kprobe bridge |

---

## Code to remove from existing files

### `pkg/appolly/discover/finder.go`

Remove the `else if` branch that loads tpinjector and its import:

```go
// DELETE this import:
"go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

// DELETE this block (keep the if cfg.EBPF.SocketTracer branch above it):
} else if cfg.EBPF.ContextPropagation.IsEnabled() {
    // FIXME: tpinjector is a backward-compatibility shim ...
    tracers = append(tracers, tpinjector.New(cfg))
}
```

### `bpf/generictracer/k_tracer.c`

Remove two `#include` lines at the top:

```c
// DELETE:
#include <common/msg_buffer.h>   // and the FIXME comment above it
#include <maps/msg_buffers.h>    // FIXME: tpinjector shim, remove with tpinjector
```

In `obi_kprobe_tcp_sendmsg`: remove the `egress_key_t e_key` declaration and the entire
`if (!size) { msg_buffer_t *m_buf = ... }` block (marked `// FIXME: tpinjector shim`),
plus the two `bpf_map_delete_elem(&msg_buffers, &e_key)` calls.

In `obi_kprobe_tcp_rate_check_app_limited`: remove the `egress_key_t e_key` declaration
and the entire `msg_buffer_t *m_buf = ...` block (marked `// FIXME: tpinjector shim`),
plus the two `bpf_map_delete_elem` calls. The `if (!ssl) { ... } else { ... }` structure
simplifies back to just `if (ssl) { tcp_send_ssl_check(...); }`.

### `Makefile`

Remove the comment added above `BPF_GEN_GO` that references tpinjector (search for
`NOTE: tpinjector generates`). The `bpf_*_bpfe[lb].go` pattern itself stays — it covers
other programs too.

---

## Verify nothing is missed

After deletion, confirm the tree is clean:

```sh
grep -r "tpinjector\|msg_buffer\|msg_buffers" \
    bpf/ pkg/ --include="*.c" --include="*.h" --include="*.go"
```

Expected: zero results (other than this file's own directory, which will be gone).

Also run:

```sh
go build ./...
make generate
```

Both must succeed without errors.
