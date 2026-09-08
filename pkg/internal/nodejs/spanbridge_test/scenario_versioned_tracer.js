'use strict';
// A tracer acquired with getTracer(name, version, options) before SDK
// registration caches the bridge Tracer; after handoff the app provider must
// receive all three original arguments, not just the name.

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

// Inject the bridge, then load the api (wired via the module-load hook).
const src = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
// eslint-disable-next-line no-eval
eval(src);

const api = require('@opentelemetry/api');
const SCHEMA_URL = 'https://example.com/1.2.3';

// Acquired BEFORE any SDK registration: caches the bridge tracer. Acquired
// through the provider, not api.trace.getTracer — the api's TraceAPI.getTracer
// itself drops the options argument (api 1.9 forwards only name+version), so
// the provider path is the only one that can carry options at all.
const tracer = api.trace.getTracerProvider().getTracer('app', '1.2.3', { schemaUrl: SCHEMA_URL });
tracer.startSpan('before').end(); // -> bridge

const appCaptured = [];
const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
const provider = new NodeTracerProvider({
  spanProcessors: [
    {
      onStart() {},
      onEnd(span) {
        appCaptured.push({
          name: span.name,
          scope: span.instrumentationScope && {
            name: span.instrumentationScope.name,
            version: span.instrumentationScope.version,
            schemaUrl: span.instrumentationScope.schemaUrl,
          },
        });
      },
      shutdown() {
        return Promise.resolve();
      },
      forceFlush() {
        return Promise.resolve();
      },
    },
  ],
});

// Spy on the provider's getTracer to capture the arguments the bridge
// forwards at handoff (the registry proxy delegates here on every call).
const forwardedArgs = [];
const origGetTracer = provider.getTracer.bind(provider);
provider.getTracer = (name, version, options) => {
  forwardedArgs.push({ name, version, options });
  return origGetTracer(name, version, options);
};

provider.register(); // -> bridge yields

// The SAME pre-acquired tracer must now route to the app provider with its
// full original identity.
tracer.startSpan('after').end();

fs.accessSync = origAccess;

process.stdout.write(
  JSON.stringify({
    bridge: bridgeCaptured,
    app: appCaptured,
    forwarded: forwardedArgs,
  })
);
