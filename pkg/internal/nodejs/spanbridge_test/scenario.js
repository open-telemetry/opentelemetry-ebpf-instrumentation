'use strict';
// Runs one span-bridge scenario in an isolated process and prints a JSON
// result ({ bridge: [...names], app: [...names] }). Isolation matters: the
// @opentelemetry/api global registry and its ProxyTracerProvider are process
// singletons, so each scenario must run in its own process to avoid bleed.
//
// The eBPF transport is stubbed by intercepting the sentinel fs.accessSync
// path the bridge uses (see spanbridge.js), so no eBPF/root is required.

const fs = require('fs');
const path = require('path');

const scenario = process.argv[2];

const bridgeCaptured = [];
// Manual-span context override/pop sentinels (-mspan/), captured as a sequence
// of raw payloads: a 48-hex <traceId><spanId> for an override, or '-' for a pop.
const mspanCaptured = [];
const origAccess = fs.accessSync;
fs.accessSync = (p, ...rest) => {
  if (typeof p === 'string' && p.startsWith('/dev/null/obi-span/')) {
    bridgeCaptured.push(JSON.parse(p.slice('/dev/null/obi-span/'.length)).name);
    const err = new Error('ENOTDIR');
    err.code = 'ENOTDIR';
    throw err;
  }
  if (typeof p === 'string' && p.startsWith('/dev/null/obi-mspan/')) {
    mspanCaptured.push(p.slice('/dev/null/obi-mspan/'.length));
    const err = new Error('ENOTDIR');
    err.code = 'ENOTDIR';
    throw err;
  }
  return origAccess(p, ...rest);
};

// Load and run the bridge the same way OBI's injector does: evaluate the file
// (it is a self-executing IIFE), rather than require()-caching it.
function injectBridge() {
  const src = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
  // eslint-disable-next-line no-eval
  eval(src);
}

const { trace } = require('@opentelemetry/api');

function makeAppSDK(appCaptured) {
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
  return new NodeTracerProvider({ spanProcessors: [proc] });
}

async function run() {
  const appCaptured = [];

  switch (scenario) {
    case 'api-only': {
      // App uses only @opentelemetry/api, no SDK: bridge should capture.
      const tracer = trace.getTracer('app');
      injectBridge();
      tracer.startSpan('s1').end();
      break;
    }
    case 'sdk-loaded-not-registered': {
      // SDK module is loaded but never registers a provider (e.g. gated off /
      // OTEL_SDK_DISABLED). "loaded" != "used": the bridge must still capture.
      require('@opentelemetry/sdk-trace-node');
      const tracer = trace.getTracer('app');
      injectBridge();
      tracer.startSpan('s1').end();
      break;
    }
    case 'sdk-already-registered': {
      // SDK registers BEFORE injection: the bridge must stay fully inert.
      makeAppSDK(appCaptured).register();
      const tracer = trace.getTracer('app');
      injectBridge();
      tracer.startSpan('s1').end();
      break;
    }
    case 'hostile-attribute': {
      // An app attribute/name whose toString() throws must NOT escape through
      // span.end() (idiomatically called in a finally block). With no SDK the
      // baseline is a silent NoopSpan, so any throw here is a regression.
      const tracer = trace.getTracer('app');
      injectBridge();
      const hostile = {
        toString() {
          throw new Error('hostile toString');
        },
      };
      let threw = null;
      try {
        const s = tracer.startSpan('s1');
        s.setAttribute('bad', hostile);
        s.setStatus({ code: 2, message: hostile });
        s.end();
      } catch (e) {
        threw = String(e && e.message);
      }
      await new Promise((r) => setTimeout(r, 20));
      fs.accessSync = origAccess;
      process.stdout.write(JSON.stringify({ bridge: bridgeCaptured, app: appCaptured, threw }));
      return;
    }
    case 'late-sdk': {
      // SDK registers AFTER injection (the race): bridge captures until the
      // app registers, then yields; the app's SDK owns telemetry afterwards,
      // including for tracers the app acquired-and-used before injection.
      const tracer = trace.getTracer('app');
      injectBridge();
      tracer.startSpan('before').end(); // -> bridge
      makeAppSDK(appCaptured).register(); // step-aside
      trace.getTracer('app').startSpan('after-new').end(); // -> app (new tracer)
      tracer.startSpan('after-preacquired').end(); // -> app (pre-acquired tracer)
      break;
    }
    case 'mspan-nesting': {
      // Active manual spans must publish the -mspan/ context override on enter
      // and restore the enclosing span (or pop to none) on exit, so OBI's eBPF
      // client spans nest under the innermost active manual span. Assert the
      // exact override/pop sequence around a nested startActiveSpan pair.
      const tracer = trace.getTracer('app');
      injectBridge();
      const label = new Map();
      tracer.startActiveSpan('outer', (outer) => {
        label.set(outer.spanContext().spanId, 'outer');
        tracer.startActiveSpan('inner', (inner) => {
          label.set(inner.spanContext().spanId, 'inner');
          inner.end();
        });
        outer.end();
      });
      const seq = mspanCaptured.map((pl) => {
        if (pl === '-') return 'pop';
        const spanId = pl.slice(32); // 48-hex payload = 32-hex traceId + 16-hex spanId
        return label.get(spanId) || 'override:' + spanId;
      });
      await new Promise((r) => setTimeout(r, 20));
      fs.accessSync = origAccess;
      process.stdout.write(JSON.stringify({ mspan: seq, bridge: bridgeCaptured }));
      return;
    }
    case 'mspan-async-release': {
      // A manual span whose scope ends inside an async callback must not leave
      // its override latched: the async_hooks 'after' boundary pops it. Without
      // that pop the last sentinel is an override, and every later eBPF client
      // span and enriched log line would carry a span that already ended.
      const tracer = trace.getTracer('app');
      injectBridge();
      await new Promise((resolve) => {
        tracer.startActiveSpan('job', (job) => {
          setTimeout(() => {
            job.end();
            resolve();
          }, 5);
        });
      });
      await new Promise((r) => setTimeout(r, 20));
      const seq = mspanCaptured.map((pl) => (pl === '-' ? 'pop' : 'override'));
      fs.accessSync = origAccess;
      process.stdout.write(JSON.stringify({ mspan: seq, bridge: bridgeCaptured }));
      return;
    }
    default:
      throw new Error('unknown scenario: ' + scenario);
  }

  await new Promise((r) => setTimeout(r, 20));
  fs.accessSync = origAccess;
  process.stdout.write(JSON.stringify({ bridge: bridgeCaptured, app: appCaptured }));
}

run().catch((e) => {
  process.stderr.write(String(e && (e.stack || e.message)));
  process.exit(1);
});
