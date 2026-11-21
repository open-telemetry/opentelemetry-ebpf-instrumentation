# Rust context propagation fixtures

This application receives a request, yields and spawns nested Tokio tasks, then
forwards the request using a persistent HTTP client. Every request has a distinct
trace ID so concurrent requests and connection reuse can expose incorrect parents.

The integration runner builds these variants with an ordinary Cargo release
profile and strips DWARF before starting OBI's generic tracer:

| Example | Incoming protocol | Outgoing protocol | Fixture feature |
| --- | --- | --- | --- |
| Tokio and reqwest | HTTP/1 | HTTP/1 or cleartext HTTP/2 | Default |
| reqwest with Rustls | HTTP/1 | HTTPS HTTP/1 or HTTP/2 | `tls` |
| Rustls server | TLS HTTP/1 or HTTP/2 | HTTPS HTTP/1 or HTTP/2 | `server,tls` |
| Older Rustls servers | TLS HTTP/2 | Cleartext HTTP/2 | `server` or `server_legacy` |
| Rustls clients 0.20–0.23 | HTTP/1 | HTTPS HTTP/1 or HTTP/2 | `rustls_client` or `rustls_client_legacy` |

The direct Rustls client examples use Hyper's HTTP/1 and HTTP/2 connection APIs,
trust the test server's certificate, and reuse the connection for concurrent
requests. The reqwest examples include its older Tokio 0.2 and Hyper 0.13/0.14
dependencies. Both Tokio scheduler configurations run for every example.

From the repository root, run a complete compiler matrix entry with Docker access:

```sh
OBI_RUST_TOOLCHAIN=1.97.1 go test -v -run '^TestRustContextPropagationMatrix$' -timeout 45m ./internal/test/integration/rustcontext
```

Or select one example:

```sh
python3 scripts/test-rust-context.py --protocols --case rustls-direct-client-0.20 --toolchain 1.97.1 --live --container
python3 scripts/test-rust-context.py --protocols --case rustls-server-0.23 --toolchain 1.100.0 --live --container
```

Version pins and protocol scenarios are defined in
[rust_versions.json](../../../../../configs/offsets/rust_versions.json).
Each fixture generates a Cargo lockfile in the selected work directory and reuses
that dependency graph for subsequent builds. Generated lockfiles are not committed.

`--fallbacks` also removes selected symbols from executable copies. These tests
exercise retained alternative hooks and verify that missing task, queue, or
protocol groups preserve partial capture. An alternative that the compiler has
also inlined is reported explicitly; the missing-group tests verify the resulting
partial capabilities. Per-scenario evidence is written under the chosen work
directory's `evidence/` directory and uploaded by CI.
