'use strict';
// Behavioral tests for ../spanbridge.js — the injected OBI Node.js manual-span
// bridge. Each scenario runs in its own process (see scenario.js) because the
// @opentelemetry/api global registry is a process singleton.
//
// Run: cd pkg/internal/nodejs/spanbridge_test && npm ci && node --test

const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

function runScenario(name) {
  const out = execFileSync(process.execPath, [path.join(__dirname, 'scenario.js'), name], {
    encoding: 'utf8',
  });
  return JSON.parse(out);
}

function runScript(file) {
  const out = execFileSync(process.execPath, [path.join(__dirname, file)], { encoding: 'utf8' });
  return JSON.parse(out);
}

test('api-only app: bridge captures manual spans', () => {
  const r = runScenario('api-only');
  assert.deepStrictEqual(r.bridge, ['s1']);
  assert.deepStrictEqual(r.app, []);
});

test('SDK loaded but never registered: bridge still captures (no false skip)', () => {
  // Depending on / loading the SDK is not the same as using it. An app that
  // migrated to OBI but left the dependency, or loaded it disabled, still
  // gets its manual spans captured.
  const r = runScenario('sdk-loaded-not-registered');
  assert.deepStrictEqual(r.bridge, ['s1']);
});

test('SDK already registered before injection: bridge stays inert', () => {
  const r = runScenario('sdk-already-registered');
  assert.deepStrictEqual(r.bridge, [], 'bridge must not capture when an SDK owns the API');
  assert.deepStrictEqual(r.app, ['s1'], 'the app SDK captures its own span');
});

test('hostile attribute/name: span.end() never throws into the app', () => {
  // A value whose toString() throws must not escape span.end() — the baseline
  // (no SDK) is a silent NoopSpan, so a throw here would be a regression that
  // could crash a request from its finally block.
  const r = runScenario('hostile-attribute');
  assert.strictEqual(r.threw, null, 'span.end() must not throw on a hostile attribute/name');
  assert.deepStrictEqual(r.bridge, ['s1'], 'the span is still captured despite the bad value');
});

test('api loaded AFTER injection: late copy is still wired, app SDK wins handoff', () => {
  // The bridge injects before @opentelemetry/api is ever required. A copy
  // loaded afterwards must have its global setters wrapped (module-load hook),
  // so the app's late SDK registration yields the bridge instead of being
  // refused as a duplicate. Without the hook, 'after' would land in the bridge.
  const r = runScript('scenario_late_load.js');
  assert.deepStrictEqual(r.bridge, ['before'], 'bridge captures only the pre-registration span');
  assert.ok(r.app.includes('after'), 'the app SDK captures spans once it registers');
  assert.ok(!r.bridge.includes('after'), 'bridge must stop capturing after the late SDK registers');
});

test('native ESM app: bridge captures and the late SDK still wins the handoff', () => {
  // `import '@opentelemetry/api'` resolves to the package's CommonJS entry, so
  // it flows through the Module._load hook: the bridge wires the copy, captures
  // the pre-registration span, and yields cleanly when the app's SDK registers.
  const r = runScript('scenario_esm.mjs');
  assert.deepStrictEqual(r.bridge, ['before'], 'bridge captures the pre-registration span in an ESM app');
  assert.ok(r.app.includes('after'), 'the app SDK captures spans once it registers');
  assert.ok(!r.bridge.includes('after'), 'bridge stops capturing after the ESM app registers its SDK');
});

test('bundled/unreachable api copy: bridge never blocks the app SDK registration', () => {
  // A bundled (inlined) api copy is invisible to the module loader, so the
  // bridge cannot wire it. Under Solution 1 the bridge never occupies the
  // global registry, so the app's own SDK still registers and takes over — the
  // property that matters. The trade-off (documented limitation) is that the
  // bundled app's manual spans are not captured.
  const r = runScript('scenario_bundled.js');
  assert.ok(r.app.includes('bundled-after'), 'the app SDK registers and captures its spans (not blocked)');
  assert.deepStrictEqual(r.bridge, [], 'bundled spans are not captured — the accepted limitation');
});

test('mixed reachable + unreachable copies: registry-appearance drives the handoff', () => {
  // A reachable copy caches our tracer (bridge emitting), while a bundled copy
  // registers the app SDK straight into the global registry, bypassing the
  // setter we wrap. Without treating the registry provider as a handoff signal,
  // the cached tracer would keep emitting OBI spans alongside the app's SDK.
  const r = runScript('scenario_mixed_copy.js');
  assert.deepStrictEqual(r.bridge, ['before'], 'bridge captures only the pre-registration span');
  assert.ok(r.app.includes('after'), "the reachable copy's cached tracer routes to the app once its provider is in the registry");
  assert.ok(!r.bridge.includes('after'), 'bridge must stop emitting once the app provider appears in the registry');
});

test('SDK registers after injection: bridge yields and the app SDK takes over', () => {
  const r = runScenario('late-sdk');
  assert.deepStrictEqual(r.bridge, ['before'], 'bridge captures only the pre-handover span');
  assert.ok(r.app.includes('after-new'), 'app SDK captures spans from newly-acquired tracers');
  assert.ok(
    r.app.includes('after-preacquired'),
    'a tracer acquired before injection also routes to the app SDK after handover'
  );
  assert.ok(
    !r.bridge.includes('after-new') && !r.bridge.includes('after-preacquired'),
    'bridge stops emitting once the app SDK is registered'
  );
});
