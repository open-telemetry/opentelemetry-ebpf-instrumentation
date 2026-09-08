// Native-ESM regression (Tyler / MrAlias): a pure-ESM app must still get
// capture + SDK handoff. The bridge is injected BEFORE @opentelemetry/api is
// ever imported; the api is then pulled in with a native `import`. Because the
// api package ships a CommonJS entry (no `import`/`node` export condition),
// that `import` resolves through the CommonJS loader, so the Module._load hook
// wires the copy: the manual span is captured, and a late SDK registration
// hands off cleanly (the bridge never occupied the global registry).
//
// Run indirectly by spanbridge.test.js (node executes this file directly).
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const require = createRequire(import.meta.url); // so the eval'd bridge can require()
const fs = require('node:fs');
const __dirname = dirname(fileURLToPath(import.meta.url));

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

// Inject the bridge FIRST — @opentelemetry/api is not imported yet.
const src = readFileSync(join(__dirname, '..', 'spanbridge.js'), 'utf8');
// eslint-disable-next-line no-eval
eval(src);

const { trace } = await import('@opentelemetry/api'); // native ESM import
trace.getTracer('app').startSpan('before').end(); // -> bridge

const appCaptured = [];
const { NodeTracerProvider } = await import('@opentelemetry/sdk-trace-node');
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
}).register(); // late SDK registration -> step-aside

trace.getTracer('app').startSpan('after').end(); // -> app SDK

await new Promise((r) => setTimeout(r, 30));
fs.accessSync = origAccess;
process.stdout.write(JSON.stringify({ bridge: bridgeCaptured, app: appCaptured }));
