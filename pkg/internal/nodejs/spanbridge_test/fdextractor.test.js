'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

function runScenario(name, env = {}) {
  const out = execFileSync(process.execPath, [path.join(__dirname, 'scenario_fdextractor.js'), name], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  return JSON.parse(out);
}

const CTX = '/dev/null/obi-ctx/';
const isCtx = (e) => e.startsWith(CTX);
const ctxFor = (fd) => `${CTX}${String(fd).padStart(4, '0')}`;
const indexesOf = (events, marker) => events.flatMap((e, i) => (e === marker ? [i] : []));
const ctxBetween = (events, from, to) => events.slice(from + 1, to).filter(isCtx);

test('microtask continuations of a request do not re-signal; macrotask continuations do', () => {
  const r = runScenario('continuations');
  const starts = indexesOf(r.events, 'start');
  const microDone = indexesOf(r.events, 'microtasks-done');
  const macroDone = indexesOf(r.events, 'macrotasks-done');
  assert.strictEqual(starts.length, 3);

  for (let i = 0; i < starts.length; i++) {
    const fd = r.handlerFds[i];
    assert.ok(fd >= 0, 'the request fd is exposed to the span bridge');
    const prior = r.events.slice(0, starts[i]).filter((e) => isCtx(e) || e === '/dev/null/obi-noreqctx');
    assert.strictEqual(prior[prior.length - 1], ctxFor(fd), 'the request is signalled before its handler runs');
    assert.ok(ctxBetween(r.events, starts[i], microDone[i]).length <= 2,
      'promise continuations on the same fd must not re-signal; only http-internal scopes may');
    assert.ok(ctxBetween(r.events, microDone[i], macroDone[i]).length >= 3,
      'every macrotask continuation re-signals, repairing any kernel-side overwrite');
  }
});

test('an outgoing write forces the next continuation to re-signal', () => {
  const r = runScenario('outgoing-write');
  const wrote = indexesOf(r.events, 'wrote');
  const after = indexesOf(r.events, 'after-write');
  assert.strictEqual(wrote.length, 3);
  for (let i = 0; i < wrote.length; i++) {
    assert.deepStrictEqual(ctxBetween(r.events, wrote[i], after[i]), [ctxFor(r.handlerFds[i])],
      'the kernel points the thread at the client span on write; the next callback must restore the server context');
  }
});

test('a write queued before connect forces a re-signal after the connect flushes it', () => {
  const r = runScenario('write-before-connect');
  const callbacks = indexesOf(r.events, 'connect-callback');
  const connected = indexesOf(r.events, 'connected');
  assert.strictEqual(callbacks.length, 3);
  for (let i = 0; i < callbacks.length; i++) {
    assert.deepStrictEqual(ctxBetween(r.events, callbacks[i], connected[i]), [ctxFor(r.handlerFds[i])],
      'the connect callback flushes the queued write, so the continuation after it must re-signal');
  }
});

test('writes queued before connect add one connect listener per socket, and none with the ctx hook off', () => {
  const hookOff = runScenario('many-writes-before-connect', { CTX_HOOK: '0' }).connectListeners;
  const hookOn = runScenario('many-writes-before-connect').connectListeners;
  assert.strictEqual(hookOff.length, 3);
  assert.deepStrictEqual(hookOn, hookOff.map((n) => n + 1),
    'the agent adds exactly one listener per connecting socket, however many writes are queued');
});

test('a reconnected socket gets its connect reset again', () => {
  const hookOff = runScenario('reconnect-before-connect', { CTX_HOOK: '0' }).connectListeners;
  const hookOn = runScenario('reconnect-before-connect').connectListeners;
  assert.strictEqual(hookOff.length, 3);
  assert.deepStrictEqual(hookOn, hookOff.map((n) => n + 1),
    'the per-socket flag must clear on connect, or a reused socket loses the reset');
});

test('interleaved keep-alive connections: each continuation sees its own request signalled', () => {
  const r = runScenario('interleave');
  const fds = new Set(r.handlerFds);
  assert.strictEqual(fds.size, 2, 'two connections with distinct fds');
  let checked = 0;
  r.events.forEach((e, i) => {
    if (!e.startsWith('handler:')) return;
    const fd = Number(e.slice('handler:'.length));
    const prior = r.events.slice(0, i).filter((x) => isCtx(x) || x === '/dev/null/obi-noreqctx');
    assert.strictEqual(prior[prior.length - 1], ctxFor(fd), `continuation of fd ${fd} ran under another request's context`);
    checked++;
  });
  assert.strictEqual(checked, 2 * 3 * 3 * 2);
});

test('non-http server: promise continuations skip, macrotask continuations re-signal', () => {
  const r = runScenario('raw-tcp');
  const [start] = indexesOf(r.events, 'start');
  const [microDone] = indexesOf(r.events, 'microtasks-done');
  assert.ok(r.events.slice(0, start).some(isCtx), 'the connection is signalled before its first continuation');
  assert.deepStrictEqual(ctxBetween(r.events, start, microDone), [], 'promise continuations on the same fd must not re-signal');
  const handlers = indexesOf(r.events, 'handler');
  assert.strictEqual(handlers.length, 3);
  let prev = microDone;
  for (const h of handlers) {
    assert.ok(r.events.slice(prev + 1, h).some(isCtx), 'each macrotask continuation refreshes the context');
    prev = h;
  }
});
