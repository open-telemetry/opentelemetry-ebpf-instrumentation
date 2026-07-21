'use strict';
// Bundled-app regression: a webpack/esbuild bundle inlines @opentelemetry/api
// into the app's single module, so at runtime the api copy is never require()d
// and never appears in require.cache or Module._load. The bridge therefore
// cannot reach it. Under Solution 1 (the bridge never occupies the global
// registry) this means the bundled app's manual spans are NOT captured — but,
// crucially, the app's OWN SDK registration is NOT blocked and takes over
// normally. (Under the old design the bridge held the global `trace` slot and
// the app's registration would be refused as a duplicate.)
//
// We reproduce "unreachable" faithfully with the REAL api: load it, then remove
// it from require.cache and never require it again, so the bridge's scan and
// Module._load hook cannot see the live copy we keep using. It still talks to
// the real globalThis[Symbol.for('opentelemetry.js.api.1')] registry, exactly
// like an inlined copy.

const fs = require('fs');
const path = require('path');

// Hold live references BEFORE the bridge is injected.
const api = require('@opentelemetry/api');
const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');

// Make the api copy unreachable to the bridge: drop it from require.cache so
// the injection-time scan misses it, and we never require() it again so the
// Module._load hook never fires for it.
for (const key of Object.keys(require.cache)) {
  if (/[\\/]@opentelemetry[\\/]api[\\/]/.test(key)) delete require.cache[key];
}

const bridgeCaptured = [];
const origAccess = fs.accessSync;
fs.accessSync = (p, ...rest) => {
  if (typeof p === 'string' && p.startsWith('/dev/null/obi-span/')) {
    bridgeCaptured.push(JSON.parse(p.slice('/dev/null/obi-span/'.length)).name);
    const err = new Error('ENOTDIR');
    err.code = 'ENOTDIR';
    throw err;
  }
  return origAccess(p, ...rest);
};

// Inject the bridge: its require.cache scan finds no api copy, and the held
// copy is never re-required, so it is never wired (the bundled case).
const src = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
// eslint-disable-next-line no-eval
eval(src);

const appCaptured = [];

// Span created through the unreachable copy before any SDK: not captured.
api.trace.getTracer('app').startSpan('bundled-before').end();

// The app registers its OWN SDK through the same unreachable copy. This must
// succeed (not be refused as a duplicate) — that is the property we assert.
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

api.trace.getTracer('app').startSpan('bundled-after').end(); // -> app SDK

setTimeout(() => {
  fs.accessSync = origAccess;
  process.stdout.write(JSON.stringify({ bridge: bridgeCaptured, app: appCaptured }));
}, 30);
