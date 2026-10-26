'use strict';

const fs = require('fs');
const path = require('path');

const spans = [];
const originalExistsSync = fs.existsSync;
fs.existsSync = (pathname, ...rest) => {
  if (typeof pathname === 'string' && pathname.startsWith('/dev/null/obi-span/')) {
    spans.push(JSON.parse(pathname.slice('/dev/null/obi-span/'.length)));
    return false;
  }
  return originalExistsSync(pathname, ...rest);
};

const modulePath = path.join(__dirname, 'scenario_dynamic_module.js');
const lateModulePath = path.join(__dirname, 'scenario_dynamic_late_module.js');
const loaded = require(modulePath);
const appSpans = [];
const diagnostics = [];
const originalEmitWarning = process.emitWarning;

if (process.argv[2].startsWith('app-sdk')) {
  const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
  new NodeTracerProvider({
    spanProcessors: [{
      onStart(span) {
        if (process.argv[2] === 'app-sdk-end-throws') {
          span.end = () => {
            throw new Error('expected span end failure');
          };
        }
      },
      onEnd(span) {
        appSpans.push(span.name);
      },
      shutdown() {
        return Promise.resolve();
      },
      forceFlush() {
        return Promise.resolve();
      },
    }],
  }).register();
}

const bridgeCode = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
// eslint-disable-next-line no-eval
eval(bridgeCode);

if (process.argv[2] === 'selected' || process.argv[2].startsWith('app-sdk')) {
  if (process.argv[2] !== 'app-sdk-end-throws') process.env.OTEL_EBPF_NODEJS_DEBUG = '1';
  process.emitWarning = (warning, options) => {
    if (options && options.code === 'OBI_DYNAMIC_SPAN_TARGET') {
      diagnostics.push({ message: String(warning), code: options.code });
    } else {
      originalEmitWarning(warning, options);
    }
  };
  const rules = [
    { name: 'dynamic.sync', moduleSpecifier: modulePath, exportPath: ['sync'] },
    { name: 'dynamic.async', moduleSpecifier: modulePath, exportPath: ['async'] },
    { name: 'dynamic.fail', moduleSpecifier: modulePath, exportPath: ['fail'] },
    { name: 'dynamic.missing', moduleSpecifier: modulePath, exportPath: ['missing'] },
    { name: 'dynamic.proxy-failure', moduleSpecifier: modulePath, exportPath: ['proxyFailure'] },
    { name: 'dynamic.callable-parent', moduleSpecifier: modulePath, exportPath: ['callable', 'nested', 'work'] },
    { name: 'dynamic.late', moduleSpecifier: lateModulePath, exportPath: ['nested', 'work'] },
  ];
  const dynamicCode = fs
    .readFileSync(path.join(__dirname, '..', 'dynamic_spans.js'), 'utf8')
    .replace('__OBI_DYNAMIC_SPAN_RULES__', JSON.stringify(rules));
  // eslint-disable-next-line no-eval
  eval(dynamicCode);
  require(modulePath);
}

async function run() {
  const values = [loaded.sync(1), await loaded.async(2)];
  let thrown = '';
  try {
    loaded.fail();
  } catch (err) {
    thrown = err.message;
  }
  const late = require(lateModulePath).nested.work();
  const callable = loaded.callable.nested.work();
  await new Promise((resolve) => setImmediate(resolve));
  fs.existsSync = originalExistsSync;
  process.emitWarning = originalEmitWarning;
  process.stdout.write(JSON.stringify({
    values,
    thrown,
    late,
    callable,
    appSpans,
    diagnostics,
    spans: spans.map((span) => ({ name: span.name, status: span.status, attrs: span.attrs })),
  }));
}

run().catch((err) => {
  process.stderr.write(String(err && (err.stack || err.message)));
  process.exit(1);
});
