'use strict';
// Regression for the late-loaded-@opentelemetry/api handoff:
// the bridge is injected BEFORE @opentelemetry/api is ever require()d, so the
// api copy is NOT in require.cache when the bridge wires up. A copy loaded
// afterwards must still get its global setters wrapped (via the module-load
// hook) so the application's own SDK registration wins the handoff instead of
// being refused as a duplicate. Without the hook the app SDK never registers
// and 'after' would be captured by the bridge, not the app.
//
// Runs in its own process (the api global registry is a process singleton) and
// deliberately does NOT import @opentelemetry/api at the top.

const fs = require('fs');
const path = require('path');

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

// Inject the bridge FIRST — @opentelemetry/api is not loaded yet.
(function injectBridge() {
  const src = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
  // eslint-disable-next-line no-eval
  eval(src);
})();

async function run() {
  const appCaptured = [];

  // First load of the api happens AFTER injection -> the module-load hook must
  // wire this copy so its setGlobalTracerProvider is wrapped.
  const { trace } = require('@opentelemetry/api');
  const tracer = trace.getTracer('app');
  tracer.startSpan('before').end(); // -> bridge (no SDK yet)

  // The app registers its own SDK late, through the same (late-loaded) api.
  const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
  const proc = {
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
  };
  new NodeTracerProvider({ spanProcessors: [proc] }).register(); // step-aside

  trace.getTracer('app').startSpan('after').end(); // -> app SDK

  await new Promise((r) => setTimeout(r, 20));
  fs.accessSync = origAccess;
  process.stdout.write(JSON.stringify({ bridge: bridgeCaptured, app: appCaptured }));
}

run().catch((e) => {
  process.stderr.write(String(e && (e.stack || e.message)));
  process.exit(1);
});
