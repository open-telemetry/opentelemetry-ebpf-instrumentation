'use strict';
// Runs one span-bridge scenario in an isolated process and prints a JSON
// result ({ bridge: [...names], app: [...names] }). Isolation matters: the
// @opentelemetry/api global registry and its ProxyTracerProvider are process
// singletons, so each scenario must run in its own process to avoid bleed.
//
// The eBPF transport is stubbed by intercepting the sentinel fs.existsSync
// path the bridge uses (see spanbridge.js), so no eBPF/root is required.

const fs = require('fs');
const path = require('path');

const scenario = process.argv[2];

const bridgeCaptured = [];
const bridgeFds = [];
const bridgeIds = [];
const SPAN_PREFIX = '/dev/null/obi-span/';
const SPAN_FD_PREFIX = '/dev/null/obi-spanfd/';
const FD_DIGITS = 4;
// The real fs.existsSync returns false for the sentinel path rather than
// throwing. It can still throw under Node's permission model, which is what
// the 'throwing-transport' scenario reproduces.
let transportThrows = false;
const origExists = fs.existsSync;
fs.existsSync = (p, ...rest) => {
  if (typeof p === 'string' && (p.startsWith(SPAN_FD_PREFIX) || p.startsWith(SPAN_PREFIX))) {
    let json;
    if (p.startsWith(SPAN_FD_PREFIX)) {
      bridgeFds.push(p.slice(SPAN_FD_PREFIX.length, SPAN_FD_PREFIX.length + FD_DIGITS));
      json = p.slice(SPAN_FD_PREFIX.length + FD_DIGITS);
    } else {
      bridgeFds.push(null);
      json = p.slice(SPAN_PREFIX.length);
    }
    const rec = JSON.parse(json);
    bridgeCaptured.push(rec.name);
    bridgeIds.push({ tid: rec.tid, sid: rec.sid });
    if (transportThrows) {
      const err = new Error('permission denied by policy');
      err.code = 'ERR_ACCESS_DENIED';
      throw err;
    }
    return false;
  }
  return origExists(p, ...rest);
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
    case 'throwing-transport': {
      // fs.existsSync throwing must not escape span.end(), which applications
      // idiomatically call from a finally block.
      const tracer = trace.getTracer('app');
      injectBridge();
      transportThrows = true;
      let threw = null;
      try {
        tracer.startSpan('s1').end();
      } catch (e) {
        threw = String(e && e.message);
      }
      await new Promise((r) => setTimeout(r, 20));
      transportThrows = false;
      fs.existsSync = origExists;
      process.stdout.write(JSON.stringify({ bridge: bridgeCaptured, app: appCaptured, threw }));
      return;
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
      fs.existsSync = origExists;
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
    case 'request-fd': {
      const store = { fd: -1 };
      globalThis[Symbol.for('otel-ebpf-instrumentation.fdextractor')] = { requestFd: () => store.fd };
      const tracer = trace.getTracer('app');
      injectBridge();
      store.fd = 42;
      tracer.startSpan('in-request').end();
      store.fd = -1;
      tracer.startSpan('no-request').end();
      store.fd = 12345;
      tracer.startSpan('fd-too-wide').end();
      break;
    }
    case 'no-fdextractor': {
      const tracer = trace.getTracer('app');
      injectBridge();
      tracer.startSpan('s1').end();
      break;
    }
    case 'id-pool': {
      const tracer = trace.getTracer('app');
      injectBridge();
      for (let i = 0; i < 400; i++) tracer.startSpan('s').end();
      break;
    }
    default:
      throw new Error('unknown scenario: ' + scenario);
  }

  await new Promise((r) => setTimeout(r, 20));
  fs.existsSync = origExists;
  process.stdout.write(JSON.stringify({ bridge: bridgeCaptured, app: appCaptured, fds: bridgeFds, ids: bridgeIds }));
}

run().catch((e) => {
  process.stderr.write(String(e && (e.stack || e.message)));
  process.exit(1);
});
