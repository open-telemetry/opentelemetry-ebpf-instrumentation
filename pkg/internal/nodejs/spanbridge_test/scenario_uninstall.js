'use strict';
// The shutdown pass: injecting the bridge with its gate off must undo a prior
// gated injection — Module._load and the wrapped api setters restored by
// identity, and no further spans reaching the transport.

const fs = require('fs');
const path = require('path');
const Module = require('module');

const api = require('@opentelemetry/api');

const captured = [];
const origExists = fs.existsSync;
fs.existsSync = (p, ...rest) => {
  if (typeof p === 'string' && p.startsWith('/dev/null/obi-span/')) {
    captured.push(JSON.parse(p.slice('/dev/null/obi-span/'.length)).name);
    return false;
  }
  return origExists(p, ...rest);
};

const src = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
const enabled = src.replace('= false; /*OBI_SPANS_ENABLED*/', '= true; /*OBI_SPANS_ENABLED*/');

const pristineLoad = Module._load;
const pristineSetTP = api.trace.setGlobalTracerProvider;
const pristineSetCM = api.context.setGlobalContextManager;

eval(enabled);

const installed = {
  active: !!globalThis.__obiSpanBridge,
  loadPatched: Module._load !== pristineLoad,
  setTPWrapped: api.trace.setGlobalTracerProvider !== pristineSetTP,
  setCMWrapped: api.context.setGlobalContextManager !== pristineSetCM,
};

api.trace.getTracer('t').startSpan('before').end();
const afterInstall = captured.length;

eval(src);

const removed = {
  globalCleared: globalThis.__obiSpanBridge === undefined,
  latchCleared: globalThis.__obiSpanBridgeLoaded === false,
  loadRestored: Module._load === pristineLoad,
  setTPRestored: api.trace.setGlobalTracerProvider === pristineSetTP,
  setCMRestored: api.context.setGlobalContextManager === pristineSetCM,
};

for (let i = 0; i < 20; i++) {
  api.trace.getTracer('t').startSpan('after').end();
}

fs.existsSync = origExists;

process.stdout.write(
  JSON.stringify({
    installed,
    removed,
    emittedWhileInstalled: afterInstall,
    emittedAfterUninstall: captured.length - afterInstall,
  }),
);
