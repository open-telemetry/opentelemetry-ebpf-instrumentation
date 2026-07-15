const STORE = Symbol.for('otel-ebpf-instrumentation.fdextractor');

const net = require('net');
const fs = require('fs');

if (!global[STORE]) {
  global[STORE] = {
    serverEmit: net.Server.prototype.emit,
    socketConnect: net.Socket.prototype.connect,
    socketWrite: net.Socket.prototype.write,
  };
}

const orig = global[STORE];
net.Server.prototype.emit = orig.serverEmit;
net.Socket.prototype.connect = orig.socketConnect;
net.Socket.prototype.write = orig.socketWrite;

const { AsyncLocalStorage, createHook } = require('async_hooks');

const debug_enabled = false;

console.log('OpenTelemetry eBPF Instrumentation has injected instrumentation via the NodeJS debugger');
console.log('The debugger will be deactivated again and closed');

// ALS store holds only incomingFd
const als = new AsyncLocalStorage();

net.Server.prototype.emit = function (event, ...args) {
  if (event === 'connection') {
    const socket = args[0];
    const incomingFd = socket._handle && socket._handle.fd;

    if (debug_enabled) {
      console.log(
        `[incoming TCP] fd:${incomingFd}, remote=${socket.remoteAddress}:${socket.remotePort}`,
      );
    }

    return als.run({ incomingFd }, () =>
      orig.serverEmit.call(this, event, ...args),
    );
  }
  return orig.serverEmit.call(this, event, ...args);
};

const pad4 = n => String(n).padStart(4, '0');

function correlate(incomingFd, outFd, socket) {
  if (incomingFd < 0 || outFd < 0 || incomingFd === outFd) {
    return Promise.resolve();
  }

  if (debug_enabled) {
    const addr = socket.remoteAddress || 'unknown';
    const port = socket.remotePort || 'unknown';

    console.log(
      `[outgoing TCP] inFd:${incomingFd}, outFd:${outFd}, to=${addr}:${port}`,
    );
  }

  try {
    fs.accessSync(`/dev/null/obi/${pad4(incomingFd)}${pad4(outFd)}`)
  } catch (err) {
  }
}

net.Socket.prototype.connect = function (...args) {
  const store = als.getStore();
  const sock = this;
  const result = orig.socketConnect.apply(this, args);

  if (store) {
    sock.once('connect', () => {
      const outFd = sock._handle && sock._handle.fd;
      correlate(store.incomingFd, outFd, sock);
    });
  }

  return result;
};

net.Socket.prototype.write = function (data, ...rest) {
  const doWrite = () => orig.socketWrite.apply(this, [data, ...rest]);

  // skip ipc writes
  if (
    this === process.stdout ||
    this === process.stderr
  ) {
    return doWrite();
  }

  const store = als.getStore();

  if (store) {
    const outFd = this._handle && this._handle.fd;
    correlate(store.incomingFd, outFd, this);
  }

  return doWrite();
};

// Signal the BPF layer before each async callback so it can restore the correct
// trace context for this request into traces_ctx_v1.
// fs.accessSync is safe inside async_hooks callbacks: synchronous fs operations
// do not create AsyncWrap objects and therefore do not re-trigger this hook.
//
// When a callback fires OUTSIDE any request (e.g. a background timer, or a
// callback that ran after its request finished), the kernel map would otherwise
// still hold the last request's context — so a manual span ending in that
// callback (bpf/generictracer/nodejs.c: obi_ctx__get) would be mis-parented
// into that stale trace. We therefore emit an explicit clear when leaving
// request scope. To avoid a synchronous syscall on every non-request callback
// (there can be very many), we only clear on the request -> no-request
// transition, tracked by `ctxActive`; a subsequent request callback re-sets it.
let ctxActive = false;
createHook({
  before() {
    const store = als.getStore();
    if (store && store.incomingFd != null && store.incomingFd >= 0) {
      ctxActive = true;
      try {
        fs.accessSync(`/dev/null/obi-ctx/${pad4(store.incomingFd)}`);
      } catch (_) {}
    } else if (ctxActive) {
      ctxActive = false;
      try {
        // Explicit "no request context" signal: obi_uv_fs_access deletes the
        // traces_ctx_v1 entry so later spans are not parented into a stale trace.
        fs.accessSync('/dev/null/obi-noreqctx');
      } catch (_) {}
    }
  },
}).enable();
