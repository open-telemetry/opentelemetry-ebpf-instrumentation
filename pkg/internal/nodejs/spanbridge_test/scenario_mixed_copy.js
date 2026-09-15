'use strict';
// Mixed reachable + unreachable @opentelemetry/api copies:
// the bridge wires and captures through a REACHABLE copy, while the app
// registers its SDK through a SECOND, bundled/unreachable copy whose
// setGlobalTracerProvider the bridge never wrapped. That registration writes
// the shared global registry directly, bypassing our setter, so `yielded`
// would never flip on its own — and the reachable copy's cached tracer (an
// OTel ProxyTracer caches our delegate on first use) would keep exporting
// through OBI while the app's SDK also runs, splitting telemetry across two
// providers in one process.
//
// The bridge must instead treat the app provider appearing in the global
// registry as a handoff signal: the reachable copy's cached tracer stops
// emitting OBI spans and routes to the app provider.
//
// Runs in its own process (the api global registry is a process singleton).

const fs = require('fs');
const path = require('path');

// Unreachable copy B and its SDK: load them, then drop @opentelemetry/api from
// require.cache so the bridge can neither scan nor hook this instance. The SDK
// keeps its reference to copy B and will register through it.
const apiBundled = require('@opentelemetry/api');
const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
void apiBundled; // held only to mirror a bundle keeping its own inlined copy
for (const key of Object.keys(require.cache)) {
  if (/[\\/]@opentelemetry[\\/]api[\\/]/.test(key)) delete require.cache[key];
}

const bridgeCaptured = [];
const origExists = fs.existsSync;
fs.existsSync = (p, ...rest) => {
  if (typeof p === 'string' && p.startsWith('/dev/null/obi-span/')) {
    bridgeCaptured.push(JSON.parse(p.slice('/dev/null/obi-span/'.length)).name);
    return false;
  }
  return origExists(p, ...rest);
};

// Inject the bridge. apiBundled is not in require.cache, so it is never wired.
const src = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8').replace('= false; /*OBI_SPANS_ENABLED*/', '= true; /*OBI_SPANS_ENABLED*/');
// eslint-disable-next-line no-eval
eval(src);

// REACHABLE copy A: required AFTER injection, so the module-load hook wires it
// (its ProxyTracerProvider delegates to the bridge). It is a fresh instance
// because the cache was cleared above.
const apiReachable = require('@opentelemetry/api');
const tracer = apiReachable.trace.getTracer('reachable'); // caches the bridge delegate
tracer.startSpan('before').end(); // -> bridge (no app provider registered yet)

const appCaptured = [];

// The app registers its SDK through the UNREACHABLE copy B (its
// setGlobalTracerProvider was never wrapped), writing the shared registry
// directly — the case that bypasses our setter.
new NodeTracerProvider({
  spanProcessors: [
    {
      onStart() {},
      onEnd(span) {
        appCaptured.push(span.name);
      },
      shutdown() {
        return Promise.resolve();
      },
      forceFlush() {
        return Promise.resolve();
      },
    },
  ],
}).register();

// The SAME cached tracer from the reachable copy emits again. With the
// registry-appearance handoff it must route to the app provider, NOT the
// bridge.
tracer.startSpan('after').end();

setTimeout(() => {
  fs.existsSync = origExists;
  process.stdout.write(JSON.stringify({ bridge: bridgeCaptured, app: appCaptured }));
}, 30);
