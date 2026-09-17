# Deno trace-context propagation — the human version

Status: **proposal**. This is the short introduction; the
[technical design](deno-context-propagation.md) remains the source of truth.

## The goal

We want OpenTelemetry eBPF Instrumentation (OBI) to connect a Deno server request to
the HTTP call it makes downstream, just as it already does for Node.js. The result
should appear as one coherent distributed trace instead of unrelated spans.

Users should not have to change or restart their service with special options. In
particular, the design must not require `--inspect`, `--inspect-brk`, Deno's native
OpenTelemetry flags, application changes, or an OTLP exporter inside the service.

The important correctness rule is simple: when OBI cannot prove the relationship, it
must leave the calls uncorrelated. Associating a call with the wrong request is worse
than producing two separate traces.

## Why this is harder than Node.js

Our Node.js solution relies on runtime details that Deno does not share:

- Node exposes network sockets and their file descriptors to JavaScript. Native Deno
  `fetch` is implemented in Rust and exposes neither.
- Node uses libuv, which gives OBI a cheap way to signal a relationship from the
  injected agent to eBPF. Deno does not use libuv.
- Node provides a reliable HTTP request event that an agent can patch after the server
  has started. Native `Deno.serve` does not currently expose an equivalent
  retroactive request-entry hook.
- Node uses OpenSSL for HTTPS. Deno uses statically linked rustls, so the kernel sees
  encrypted TLS records rather than HTTP headers.

OBI can still open Deno's inspector automatically and inject an agent after startup.
The difficult part is finding stable places where that agent can identify the current
request and communicate it to eBPF safely.

## What the experiments found

We tested against Deno 2.9.4, injecting the agent only after the server was already
accepting traffic — the same constraint OBI has with a running user service. Each
inbound request waited asynchronously and then called a separate upstream process.
We compared sequential traffic with 40 concurrent requests and varied whether the
handler read its incoming `Request`.

Without a Deno-specific agent, sequential traffic can look correct because OBI often
associates work with the request currently running on the thread. Under concurrency
that shortcut breaks down: only about 1 of 40 outbound calls was attached to the
right server trace.

For native `Deno.serve`, a late patch of properties such as `request.url` can discover
the remote peer and establish the right asynchronous context. Requests that touched
one of those properties correlated 40 out of 40 times. The crucial control case
failed, however: a handler that never touched its `Request` could inherit another
handler's context and produce a wrong parent. Attempts to clear that state at request
completion also failed, so the property-access technique is not safe to ship alone.

Deno's Node compatibility API behaved differently. Its
`http.Server.prototype.emit('request')` event provides a real boundary that can be
wrapped with `AsyncLocalStorage.run()`, naturally limiting the context to one request.
This validates the compatibility ingress approach, although the new outbound-header
mechanism still needs its own end-to-end tests.

The experiments also confirmed two useful building blocks:

- Plain HTTP `fetch` writes a normal HTTP header block that eBPF can inspect and
  rewrite before it leaves the machine.
- Deno's inspector supports waiting for an injected promise. OBI must use that
  facility and make the agent return a structured result; otherwise a failed async
  installation can terminate the Deno process.

## The proposed HTTP mechanism

For plaintext HTTP, the design has three steps:

1. The injected agent records which inbound connection belongs to the current async
   request.
2. Before an outbound HTTP call, the agent adds a fixed-length, authenticated and
   opaque placeholder `traceparent`. It never replaces a header already set by the
   application or an SDK, and it never adds the placeholder to HTTPS.
3. OBI's kernel-side eBPF program authenticates the placeholder, finds the
   corresponding server span, generates the real client trace context, and overwrites
   the placeholder in place.

The JavaScript agent never chooses OBI's final trace or span IDs. eBPF remains the
source of truth.

For IPv4, the masked reference fits directly in the existing `traceparent` span
ID, so the first implementation needs no connection-index map. Native IPv6 can add an
indexed reference later without changing the wire format.

If OBI disappears before seeing a placeholder, the downstream receives a unique,
random-looking W3C context. It reveals no address, port, stable token, or recognizable
OBI marker, and it cannot merge the call into another OBI trace.

## How we plan to deliver it

The work is split into small, independently reviewable pull requests:

1. Add a real native `denoserver` test container and a deterministic, separate
   `denoupstream` that records the received header.
2. Add reliable Deno-specific agent injection, still dormant and with no propagation
   hooks enabled.
3. Implement and cross-test the authenticated placeholder codec in JavaScript and
   eBPF.
4. Add the gated eBPF lookup and rewrite path. It remains inactive for production
   processes at this point.
5. Deliver the first complete slice: Deno `node:http` server to `node:http` client.
6. Add native HTTP `fetch` as an egress option from a `node:http` request. This is the
   first sensible release boundary.
7. Add native IPv6 if CI can exercise the real IPv6 socket path reliably.
8. Enable native `Deno.serve` ingress only after we have proved a stable retroactive
   request boundary. We will not ship the known-unsafe accessor-only approach as a
   partial solution.

Every functional slice includes concurrent end-to-end tests, keep-alive reuse,
existing-header behaviour, late attachment, partial failure, and explicit checks that
HTTPS never receives an HTTP placeholder.

## Why HTTPS is a separate phase

The HTTP solution works because eBPF can rewrite plaintext bytes. With Deno HTTPS,
rustls encrypts the request before the socket hook sees it. Adding the same placeholder
would send it unchanged inside the encrypted request, which is unacceptable.

HTTPS therefore needs a different control path that obtains the final context before
encryption. The leading options are a persistent, authenticated inspector bridge or a
stable hook provided by the Deno runtime. We will choose and prototype that primitive
after the HTTP work; we will not rely on brittle, version-specific rustls offsets.

## The practical decision

We can start the HTTP foundations and the safe `node:http` path now. Native
`Deno.serve` remains gated on a correct request boundary, and HTTPS remains future
work with its own design phase.

This ordering gives us useful Deno coverage early without asking users to reconfigure
their services and without trading missing correlations for incorrect ones.
