// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'fdextractor.js'), 'utf8');

function harness({ legacy = false } = {}) {
  class Server extends EventEmitter {}
  class Socket extends EventEmitter {
    constructor(fd) {
      super();
      this._handle = { fd };
      this.destroyed = false;
      this.destroyCalls = 0;
    }
    connect() { return this; }
    write() { return true; }
    _destroy(err, callback) {
      this.destroyCalls++;
      this.destroyed = true;
      this._handle = null;
      callback(err);
      this.emit('close');
    }
    close() { this._destroy(null, () => {}); }
  }
  const originalDestroy = Socket.prototype._destroy;
  const signals = [];
  const context = vm.createContext({
    process,
    require(name) {
      if (name === 'net') return { Server, Socket };
      if (name === 'fs') return { existsSync(file) { signals.push(file); return false; } };
      if (name === 'perf_hooks') return { ...require(name), performance: { now: () => 0 } };
      return require(name);
    },
  });
  context.global = context;
  if (legacy) {
    vm.runInContext(`global[Symbol.for('otel-ebpf-instrumentation.fdextractor')] = {
      serverEmit: require('net').Server.prototype.emit,
      socketConnect: require('net').Socket.prototype.connect,
      socketWrite: require('net').Socket.prototype.write,
    };`, context);
  }
  const load = (traces = true) => vm.runInContext(source.replace(
    '= false; /*OBI_TRACES_ENABLED*/', `= ${traces}; /*OBI_TRACES_ENABLED*/`,
  ), context);
  const request = (incomingFd, callback) => {
    const server = new Server();
    server.once('connection', callback);
    server.emit('connection', new Socket(incomingFd));
  };
  load();
  return {
    Socket, signals, load, request, originalDestroy,
    cache: () => vm.runInContext("global[Symbol.for('otel-ebpf-instrumentation.fdextractor')].fdCache", context),
    write: (incomingFd, socket) => request(incomingFd, () => socket.write('request')),
  };
}

test('reinjection with traces disabled clears cached sockets', () => {
  const h = harness();
  const socket = new h.Socket(20);
  h.write(10, socket);
  const cache = h.cache();
  assert.equal(cache.size, 1);
  h.load(false);
  assert.equal(cache.size, 0);
  assert.equal(h.Socket.prototype._destroy, h.originalDestroy);
  h.write(10, socket);
  assert.equal(cache.size, 0);
  assert.equal(h.signals.length, 1);
});

test('an old socket close does not remove a reused fd belonging to another socket', () => {
  const h = harness();
  const oldSocket = new h.Socket(20);
  const newSocket = new h.Socket(20);
  h.write(10, oldSocket);
  h.write(11, newSocket);
  oldSocket.close();
  assert.equal(h.cache().get(20).socket, newSocket);
  newSocket.close();
  assert.equal(h.cache().size, 0);
});

test('mapping changes and reinjections add no close listeners and preserve teardown', () => {
  const h = harness();
  const socket = new h.Socket(20);
  for (let i = 0; i < 20; i++) {
    h.write(10, socket);
    h.write(11, socket);
    h.load();
  }
  h.write(10, socket);
  assert.equal(socket.listenerCount('close'), 0);
  socket.close();
  assert.equal(h.cache().size, 0);
  assert.equal(socket.destroyCalls, 1);
});

test('reconnecting the same socket installs cleanup for its new fd', () => {
  const h = harness();
  const socket = new h.Socket(20);
  h.write(10, socket);
  socket.close();
  socket.destroyed = false;
  socket._handle = { fd: 21 };
  h.request(10, () => socket.connect());
  socket.emit('connect');
  assert.equal(h.cache().get(21).socket, socket);
  assert.equal(socket.listenerCount('close'), 0);
  socket.close();
  assert.equal(h.cache().size, 0);
});

test('a connect callback from an earlier injection cannot refill a disabled cache', () => {
  const h = harness();
  const socket = new h.Socket(20);
  h.request(10, () => socket.connect());
  h.load(false);
  socket.emit('connect');
  assert.equal(h.cache().size, 0);
  assert.equal(h.signals.length, 0);
});

test('writes after close do not retain destroyed sockets again', () => {
  const h = harness();
  const socket = new h.Socket(20);
  h.write(10, socket);
  socket.close();
  h.write(10, socket);
  assert.equal(h.cache().size, 0);
  assert.equal(h.signals.length, 1);
});

test('writes before fd assignment do not prevent cleanup of the connected socket', () => {
  const h = harness();
  const socket = new h.Socket(null);
  h.write(10, socket);
  socket._handle.fd = 20;
  h.write(10, socket);
  socket.close();
  assert.equal(h.cache().size, 0);
  assert.deepEqual(h.signals, ['/dev/null/obi/00100020']);
});

test('reinjection over an older agent preserves the original teardown method', () => {
  const h = harness({ legacy: true });
  const socket = new h.Socket(20);
  h.write(10, socket);
  socket.close();
  assert.equal(h.cache().size, 0);
  assert.equal(socket.destroyCalls, 1);
  h.load(false);
  assert.equal(h.Socket.prototype._destroy, h.originalDestroy);
});

test('teardown forwards errors and callbacks even without a socket handle', () => {
  const h = harness();
  for (const fd of [20, null]) {
    const socket = new h.Socket(fd);
    h.write(10, socket);
    if (fd === null) socket._handle = null;
    const error = new Error('socket failure');
    let callbackCalls = 0;
    socket._destroy(error, (err) => {
      assert.equal(err, error);
      callbackCalls++;
    });
    assert.equal(callbackCalls, 1);
    assert.equal(socket.destroyCalls, 1);
    assert.equal(h.cache().size, 0);
  }
});
