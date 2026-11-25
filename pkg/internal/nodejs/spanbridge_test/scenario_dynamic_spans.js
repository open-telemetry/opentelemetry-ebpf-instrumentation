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
const bufferSpanName = `dynamic.buffer-length.${'x'.repeat(140)}`;
const loaded = require(modulePath);
const retainedCrypto = require('crypto');
const originalConstructor = loaded.ExampleConstructor;
const originalConstructorPrototype = originalConstructor.prototype;
const appSpans = [];
const diagnostics = [];
let callableProxyPrototypeTrapsAfterReinjection = null;
const originalEmitWarning = process.emitWarning;
const mode = process.argv[2];
const apiBeforeBridge = mode === 'dynamic-only' ? require('@opentelemetry/api') : null;
const contextOnlyApi = mode === 'context-late-provider' ? require('@opentelemetry/api') : null;

if (contextOnlyApi) {
  contextOnlyApi.context.setGlobalContextManager({
    active: () => contextOnlyApi.ROOT_CONTEXT,
    with: (_context, fn, thisArg, ...args) => Reflect.apply(fn, thisArg, args),
    bind: (_context, target) => target,
    disable() {},
  });
}

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

if (mode === 'selected' || mode === 'reinject-dynamic' || mode.startsWith('dynamic-only') || mode.startsWith('app-sdk') || mode === 'context-late-provider') {
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
    { name: 'dynamic.promise-return', reference: `${modulePath}:exports.promiseWithThenGetter` },
    { name: 'dynamic.fail', reference: `${modulePath}:exports.fail` },
    { name: 'dynamic.missing', reference: `${modulePath}:exports.missing` },
    { name: 'dynamic.proxy-failure', reference: `${modulePath}:exports.proxyContainer.failure` },
    { name: 'dynamic.proxy-prototype', reference: `${modulePath}:exports.proxyInPrototype.failure` },
    { name: 'dynamic.callable-parent', reference: `${modulePath}:exports.callable` },
    { name: 'dynamic.callable-nested', reference: `${modulePath}:exports.callable.nested.work` },
    { name: 'dynamic.callable-proxy', reference: `${modulePath}:exports.callableProxy` },
    { name: 'dynamic.constructor', reference: `${modulePath}:exports.ExampleConstructor` },
    { name: 'dynamic.random-bytes', reference: 'node:crypto:exports.randomBytes' },
    { name: 'dynamic.exists-sync', reference: 'node:fs:exports.existsSync' },
    { name: 'dynamic.clock', reference: 'node:process:exports.hrtime.bigint' },
    { name: bufferSpanName, reference: 'node:buffer:exports.Buffer.byteLength' },
    { name: 'dynamic.buffer-from', reference: 'node:buffer:exports.Buffer.from' },
    { name: 'dynamic.entry', reference: `${__filename}:exports.entryTarget` },
    { name: 'dynamic.late', reference: `${lateModulePath}:exports.nested.work` },
  ];
  const dynamicCode = fs
    .readFileSync(path.join(__dirname, '..', 'dynamic_spans.js'), 'utf8')
    .replace('__OBI_DYNAMIC_SPAN_RULES__', JSON.stringify(rules));
  // eslint-disable-next-line no-eval
  eval(dynamicCode);
  if (mode === 'reinject-dynamic') {
    // Identical reinjection must be a no-op; adding a new rule must extend the
    // active rule set without wrapping existing exports twice.
    eval(dynamicCode);
    const additionalCode = fs
      .readFileSync(path.join(__dirname, '..', 'dynamic_spans.js'), 'utf8')
      .replace('__OBI_DYNAMIC_SPAN_RULES__', JSON.stringify([
        { name: 'dynamic.sync.additional', reference: `${modulePath}:exports.sync` },
      ]));
    eval(additionalCode);
    callableProxyPrototypeTrapsAfterReinjection = loaded.callableProxyPrototypeTraps();
  }
  require(modulePath);
  if (mode === 'context-late-provider') {
    const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
    new NodeTracerProvider({
      spanProcessors: [{
        onStart() {},
        onEnd(span) { appSpans.push(span.name); },
        shutdown() { return Promise.resolve(); },
        forceFlush() { return Promise.resolve(); },
      }],
    }).register();
  }
  if (mode.startsWith('dynamic-only')) {
    const api = apiBeforeBridge || require('@opentelemetry/api');
    api.trace.getTracer('app').startActiveSpan('manual.disabled', (span) => span.end());
  }
}

async function run() {
  const promiseResult = loaded.promiseWithThenGetter();
  const promiseIdentityPreserved = promiseResult === loaded.promiseResult;
  const promiseThenGetterReads = loaded.thenGetterReads();
  const promiseSpanEndedAtReturn = spans.some((span) => span.name === 'dynamic.promise-return');
  const clockValue = process.hrtime.bigint();
  const bufferByteLength = Buffer.byteLength('instrumented');
  const bufferFrom = Buffer.from('instrumented').toString();
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
  const callableProxy = loaded.callableProxy();
  const proxyPrototype = loaded.proxyInPrototype.failure();
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
    promiseIdentityPreserved,
    promiseThenGetterReads,
    promiseSpanEndedAtReturn,
    clockValueType: typeof clockValue,
    bufferByteLength,
    bufferFrom,
    thrown,
    late,
    callableParent,
    callable,
    callableProxy,
    callableProxyApplyCalls: loaded.callableProxyApplyCalls(),
    callableProxyPrototypeTraps: loaded.callableProxyPrototypeTraps(),
    callableProxyPrototypeTrapsAfterReinjection,
    proxyPrototype,
    proxyTrapCount: loaded.proxyTrapCount(),
    proxyPrototypeTrapCount: loaded.proxyPrototypeTrapCount(),
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
