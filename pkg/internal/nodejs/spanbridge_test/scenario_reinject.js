'use strict';
// Re-injection ordering: async_hooks fire in enable order, and fdextractor's
// re-injection re-enables its '-ctx' hook, moving it after the bridge's
// override hook. The bridge's already-loaded path must move its own hook back
// last (rehook), or every callback's context refresh would erase the manual
// span override. Simulated with a state cell: the competing hook resets it,
// the bridge's override sets it; whichever runs LAST in a callback wins, so
// inside an async continuation of an active manual span the state must read
// 'manual'.

const fs = require('fs');
const path = require('path');
const { createHook } = require('async_hooks');

let mapState = 'none';
const origAccess = fs.accessSync;
fs.accessSync = (p, ...rest) => {
  if (typeof p === 'string' && p.startsWith('/dev/null/obi-mspan/')) {
    mapState = p.endsWith('/-') ? 'none' : 'manual';
    const err = new Error('ENOTDIR');
    err.code = 'ENOTDIR';
    throw err;
  }
  if (typeof p === 'string' && p.startsWith('/dev/null/obi-span/')) {
    const err = new Error('ENOTDIR');
    err.code = 'ENOTDIR';
    throw err;
  }
  return origAccess(p, ...rest);
};

const src = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
// eslint-disable-next-line no-eval
eval(src); // first injection

// Simulates fdextractor's re-enabled '-ctx' hook: enabled AFTER the bridge's
// hook, so without the rehook it runs last per callback and erases the
// override.
createHook({
  before() {
    mapState = 'server';
  },
}).enable();

// eslint-disable-next-line no-eval
eval(src); // re-injection -> already-loaded path must rehook

const api = require('@opentelemetry/api');
const tracer = api.trace.getTracer('app');

async function run() {
  let stateInContinuation;
  await tracer.startActiveSpan('outer', async (span) => {
    await new Promise((r) => setTimeout(r, 5));
    // Runs right after this callback's before-hooks: the bridge's override
    // must have run after the competing reset.
    stateInContinuation = mapState;
    span.end();
  });

  fs.accessSync = origAccess;
  process.stdout.write(JSON.stringify({ stateInContinuation }));
}

run().catch((e) => {
  process.stderr.write(String(e && (e.stack || e.message)));
  process.exit(1);
});
