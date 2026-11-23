'use strict';

exports.entryTarget = () => 'entry module';

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
const retainedCrypto = require('crypto');
const originalConstructor = loaded.ExampleConstructor;
const originalConstructorPrototype = originalConstructor.prototype;
const appSpans = [];
const diagnostics = [];
const originalEmitWarning = process.emitWarning;
const mode = process.argv[2];
const apiBeforeBridge = mode === 'dynamic-only' ? require('@opentelemetry/api') : null;

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

let bridgeCode = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
if (mode.startsWith('dynamic-only')) {
  bridgeCode = bridgeCode.replace('/*OBI_MANUAL_SPANS_ENABLED*/ true', '/*OBI_MANUAL_SPANS_ENABLED*/ false');
}
// eslint-disable-next-line no-eval
eval(bridgeCode);

if (mode === 'selected' || mode.startsWith('dynamic-only') || mode.startsWith('app-sdk')) {
  if (mode !== 'app-sdk-end-throws') process.env.OTEL_EBPF_NODEJS_DEBUG = '1';
  process.emitWarning = (warning, options) => {
    if (options && options.code === 'OBI_DYNAMIC_SPAN_TARGET') {
      diagnostics.push({ message: String(warning), code: options.code });
    } else {
      originalEmitWarning(warning, options);
    }
  };
  const rules = [
    { name: 'dynamic.sync', reference: '**:exports.sync' },
    { name: 'dynamic.async', reference: '**/scenario_dynamic_module.js:exports.async' },
    { name: 'dynamic.fail', reference: `${modulePath}:exports.fail` },
    { name: 'dynamic.missing', reference: `${modulePath}:exports.missing` },
    { name: 'dynamic.proxy-failure', reference: `${modulePath}:exports.proxyContainer.failure` },
    { name: 'dynamic.callable-parent', reference: `${modulePath}:exports.callable` },
    { name: 'dynamic.callable-nested', reference: `${modulePath}:exports.callable.nested.work` },
    { name: 'dynamic.constructor', reference: `${modulePath}:exports.ExampleConstructor` },
    { name: 'dynamic.random-bytes', reference: 'node:crypto:exports.randomBytes' },
    { name: 'dynamic.exists-sync', reference: 'node:fs:exports.existsSync' },
    { name: 'dynamic.entry', reference: `${__filename}:exports.entryTarget` },
    { name: 'dynamic.late', reference: `${lateModulePath}:exports.nested.work` },
  ];
  const dynamicCode = fs
    .readFileSync(path.join(__dirname, '..', 'dynamic_spans.js'), 'utf8')
    .replace('__OBI_DYNAMIC_SPAN_RULES__', JSON.stringify(rules));
  // eslint-disable-next-line no-eval
  eval(dynamicCode);
  require(modulePath);
  if (mode.startsWith('dynamic-only')) {
    const api = apiBeforeBridge || require('@opentelemetry/api');
    api.trace.getTracer('app').startActiveSpan('manual.disabled', (span) => span.end());
  }
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
  const callableParent = loaded.callable();
  const callable = loaded.callable.nested.work();
  const constructor = new loaded.ExampleConstructor('value');
  const constructorValue = constructor.describe();
  const constructorUsesOriginalNewTarget = constructor.constructedWith === originalConstructor;
  const constructorPrototypePreserved =
    loaded.ExampleConstructor.prototype === originalConstructorPrototype &&
    Object.getPrototypeOf(constructor) === originalConstructorPrototype;
  const constructorMarkerPreserved =
    Object.prototype.hasOwnProperty.call(loaded.ExampleConstructor, 'marker') &&
    loaded.ExampleConstructor.marker === 'constructor marker';
  const callableMarkerPreserved =
    Object.prototype.hasOwnProperty.call(loaded.callable, 'marker') && loaded.callable.marker === 'callable marker';
  const entry = module.exports.entryTarget();
  const randomBytesLength = retainedCrypto.randomBytes(7).length;
  const fileExists = fs.existsSync(__filename);
  await new Promise((resolve) => setImmediate(resolve));
  fs.existsSync = originalExistsSync;
  process.emitWarning = originalEmitWarning;
  process.stdout.write(JSON.stringify({
    values,
    thrown,
    late,
    callableParent,
    callable,
    proxyTrapCount: loaded.proxyTrapCount(),
    callableMarkerPreserved,
    constructorValue,
    constructorUsesOriginalNewTarget,
    constructorPrototypePreserved,
    constructorMarkerPreserved,
    entry,
    randomBytesLength,
    fileExists,
    appSpans,
    diagnostics,
    spans: spans.map((span) => ({ name: span.name, status: span.status, attrs: span.attrs })),
  }));
}

run().catch((err) => {
  process.stderr.write(String(err && (err.stack || err.message)));
  process.exit(1);
});
