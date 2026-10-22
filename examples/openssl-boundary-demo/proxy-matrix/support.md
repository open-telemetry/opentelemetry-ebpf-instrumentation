# Measured proxy support

The current PoC supports missing-header injection for a controlled HTTP/1.1
OpenSSL write. This is sufficient for direct TLS and transparent tunnels. It does
**not** yet provide general tracing through an instrumented proxy: preserving
the original header often keeps requests in one trace while bypassing the
proxy's outgoing client span.

These are live Linux amd64 fixture results, not conclusions from code inspection.
The [runner and build instructions](README.md) reproduce the matrix against the
unchanged instrumentation. Each case checks a real HTTP 200 response and exported
Collector spans. Both `--propagation disabled` and `--propagation headers` are
compared; the socket setting does not supply the missing general proxy support.

On 2026-10-22, each configuration completed all 31 scenarios: seven had the
expected complete span chain, 17 preserved context without the complete chain,
six lacked end-to-end context propagation, and one deliberately replaced context
by proxy policy. All advertised transport/proxy conditions were established.
Eight cases gained additional spans between their per-case snapshot and the
final snapshot; the classifications include those delayed spans.

## Results by situation

“Linked” means all expected parent edges are present, not merely a common trace
ID. “Context only” means the received header continues the originating trace, or
preserves the explicitly supplied header, but the complete instrumented span
chain is absent or incorrect.

| Case | Current result | Work needed beyond this fixture |
| --- | --- | --- |
| `direct-tls` | Linked client → origin | Production lifecycle, overhead and compatibility testing |
| `nginx-tls-passthrough` | Linked client → origin through TCP tunnel | Other tunnel implementations and connection lifecycle tests; there is no HTTP proxy hop to trace |
| `apache-connect` | Linked inner client → origin through plaintext CONNECT proxy | Broader CONNECT authentication and failure coverage; the CONNECT control request itself has no injected header |
| `apache-authenticated-connect` | Linked inner client → origin; unauthenticated CONNECT gets 407, Basic-authenticated CONNECT succeeds | Other authentication schemes and credential-refresh behavior |
| `unobserved-reverse-proxy` | Linked client → origin; selected endpoints continue context through the unselected HTTP proxy | Instrument the proxy to obtain its own spans, then solve per-hop parenting |
| `direct-mutual-tls` | Linked client → origin; backend verifies client certificate | Other certificate and TLS configurations |
| `nginx-mutual-tls-client` | Context only; nginx verifies client certificate | Per-hop request/upstream correlation and outgoing span parenting |
| `nginx-mutual-tls-upstream` | Context only; origin verifies proxy client certificate | Same per-hop work; client authentication is not the blocker |
| `nginx-tls-to-http` | Context only | Reconcile the forwarded header with the proxy's outgoing plaintext client span |
| `nginx-tls-to-tls` | Context only; origin parent bypasses outgoing proxy span | Reconcile the forwarded header with the proxy's outgoing TLS client span |
| `apache-tls-to-http` | Context only; incomplete proxy telemetry | Investigate Apache worker/connection capture and export, then verify all parent edges across TLS/plaintext |
| `apache-tls-to-tls` | Context only; incomplete proxy telemetry | Investigate Apache worker/connection capture and export, then outgoing TLS parenting |
| `apache-forward-http` | No missing-header insertion; separate traces | Integrate plaintext request injection/context handoff with existing socket propagation; fix absolute-form request metadata |
| `apache-forward-https-origin` | Context only; incomplete proxy telemetry and malformed client URL metadata | Handle absolute-form request targets correctly; complete proxy capture and per-hop parenting |
| `apache-https-connect` | Inner HTTPS request succeeds, but missing context is not injected; client telemetry is incomplete | Associate nested TLS/memory BIO sessions with the real connection, or intercept an HTTP serializer above TLS |
| `nginx-preserve-existing` | Caller-supplied header preserved; context only | Define OBI span adoption/parenting around application-owned headers without overwriting their identity |
| `nginx-strip-header` | Linked through nginx when its configuration strips the forwarded header before outgoing TLS injection | Validate ownership semantics before recommending a policy; blanket stripping can destroy legitimate application context |
| `nginx-replace-header` | Proxy intentionally replaces context with its configured value | Change proxy policy if continuity is wanted; instrumentation should not silently undo an explicit application policy |
| `nginx-upstream-pool` | Context only; four requests reuse one origin connection | Per-request correlation on reused connections; check timely span export |
| `nginx-concurrent` | Context only; six concurrent clients complete with their own originating context | Per-request/per-attempt parenting under concurrency, bounded export, then stress and multiplexing tests |
| `nginx-load-balance` | Context only; both origins receive requests | Correct parent edges regardless of chosen backend; verify export for every upstream |
| `nginx-retry-503` | Context only; proxy log proves 503 then 200 | Model and parent each upstream attempt; preserve the request's trace across retry attempts |
| `nginx-apache-chain` | Context reaches final origin; full chain missing | Complete capture and context handoff at every proxy hop, including Apache |
| `nginx-cache` | Context only overall; verified MISS then HIT | Correct MISS upstream chain; HIT must end at the proxy and must not reuse the cached response's old trace as the current request identity |
| `h2-client-nginx-h1-origin` | HTTP/2 ingress proven; no end-to-end missing-context propagation | Stream-aware HTTP/2 request capture and context handoff, with HPACK/frame-aware insertion or serializer hooks |
| `h1-client-apache-h2-origin` | HTTP/2 origin proven; context forwarded, full chain missing | Complete proxy HTTP/2 client observation and parenting; forwarding an existing header does not prove HTTP/2 insertion |
| `h2-client-apache-h2-origin` | HTTP/2 at both ends proven; no end-to-end missing-context propagation | HTTP/2 stream capture, HPACK/frame/header handling and per-stream context association |
| `h3-client-nginx-h1-origin` | HTTP/3 ingress proven; no end-to-end missing-context propagation | QUIC/HTTP/3 stream interception, QPACK/header handling and context handoff into the outgoing request |
| `h3-existing-context-through-nginx` | HTTP/3 ingress proven; supplied context reaches HTTP/1 origin, full chain missing | Capture originating QUIC and proxy ingress spans and parent the outgoing hop; header forwarding alone is insufficient |
| `split-headers-through-proxy` | Request succeeds, original client's missing context is not continued | Incremental HTTP/1 parsing and safe buffering/accounting across application writes, then proxy parenting |
| `tls-record-fragments-through-proxy` | Complete-header application write with 32 KiB body and 512-byte TLS records succeeds; context only | Same proxy parenting work; validate body integrity and broader retry/fragment combinations before widening supported buffer semantics |

## Evidence and interpretation

The tunnel cases preserve the inner TLS connection, so OBI can add the HTTP header
at the client and the origin can read it. A reverse proxy terminates one request
and creates another. By default it forwards the header it received. In the nginx
TLS-to-TLS fixture, the origin's parent is the original client span, bypassing the
proxy's outgoing span. The outgoing proxy span exists, but the current agent
preserves an existing header instead of replacing it with that span's identity.

The strip-header case establishes that a proxy-originated TLS request without a
header can receive OBI-owned context and link correctly in this fixture. It does
not justify stripping all user headers. A general solution must distinguish
application-owned context from OBI-owned context and correlate the inbound
request with the correct upstream attempt before deciding which span identity
to propagate.

Apache has an additional capture/export gap: successful attachment and header
forwarding did not yield a complete set of proxy server/client spans. Some spans
appeared after connections closed; others remained absent in the final snapshot.
The matrix records counts before draining and final exported spans. Fixing only
the header value will not establish Apache support; capture and export need
separate validation.

The absolute-form HTTPS forward-proxy case also exposes malformed `url.full`
metadata: OBI prepends the proxy host to an already absolute request target. The
analyzer retains `reported_target` and normalizes it only to match requests; that
does not fix the emitted attribute.

An HTTP/2 or HTTP/3 request can work at the proxy while its tracing remains
unsupported. The native HTTP/3 client uses OpenSSL for QUIC's TLS handshake, but
HTTP/3 headers travel in QUIC streams rather than ordinary `SSL_write` HTTP/1
buffers. Existing HTTP/1 header insertion therefore does not establish QUIC
support. HTTP/2 similarly requires stream and compressed-header handling.

Application-write fragmentation and TLS-record fragmentation are different
boundaries. Splitting the HTTP headers across two application writes loses the
originating context here. Keeping the headers complete in one application write
while OpenSSL emits 512-byte records preserves context in the tested request.
The latter is not a replacement for the existing native fixture's readonly-input,
partial-write, moving-buffer-retry and graceful-shutdown assertions.

## Implementation priorities

1. Establish reliable capture and export for Apache and persistent upstream
   connections; add bounded-latency assertions rather than relying on shutdown.
2. Define application-owned versus OBI-owned context, correlate inbound requests
   to upstream attempts, and emit consistent parent edges for preserve/strip/
   replace policies, reuse, retries, cache hits and multiple proxies.
3. Add incremental HTTP/1 header handling with the existing buffer/retry safety
   guarantees. Cover upgrades and streaming separately.
4. Add HTTP/2 stream/header support, nested TLS connection association, and then
   HTTP/3/QUIC support at a suitable stream or serializer boundary. These require
   implementation, not only additional validation.

Transparent tunnels and mutual TLS need broader validation rather than a new
header-insertion mechanism. General proxy parenting, split application writes,
nested TLS, and HTTP/2/HTTP/3 need code changes. These findings describe the current
PoC and do not establish an inherent limitation of using Frida in OBI.

## Protocol references

- [Apache forward and reverse proxy behavior](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html)
- [Apache CONNECT tunneling](https://httpd.apache.org/docs/2.4/mod/mod_proxy_connect.html)
- [nginx HTTP proxying, header policies, pooling, retries and caching](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [nginx TCP/UDP stream proxying](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html)
- [W3C Trace Context processing model](https://www.w3.org/TR/trace-context/#design-overview)
- [HTTP/2 streams and header blocks](https://www.rfc-editor.org/rfc/rfc9113.html)
- [HTTP/3 mapping over QUIC](https://www.rfc-editor.org/rfc/rfc9114.html)

Live validation uses Linux amd64, Frida Core 17.24.3, Go 1.27.2, nginx 1.31.7
(OpenSSL 3.5.7), Apache 2.4.69 (OpenSSL 3.5.7), Collector 0.162.0, OpenSSL CLI
3.0.13, curl 8.5.0 for HTTP/2, and the pinned curl 8.23.0/ngtcp2 1.19.0/nghttp3
1.15.0/OpenSSL 3.5.7 HTTP/3 client. arm64 compilation is checked separately;
live results do not cover arm64. Other proxy products, TLS libraries and the
untested dimensions listed in the README remain unvalidated.
