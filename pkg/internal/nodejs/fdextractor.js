(()=>{
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
  const { monitorEventLoopDelay, performance } = require('perf_hooks');

  const debug_enabled = false;

  if (debug_enabled) {
    console.log('OpenTelemetry eBPF Instrumentation has injected instrumentation via the NodeJS debugger');
    console.log('The debugger will be deactivated again and closed');
  }

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
  createHook({
    before() {
      const store = als.getStore();
      if (store && store.incomingFd != null && store.incomingFd >= 0) {
        try {
          fs.accessSync(`/dev/null/obi-ctx/${pad4(store.incomingFd)}`);
        } catch (_) {}
      }
    },
  }).enable();

  // Runtime metrics (nodejs.eventloop.*): sample the in-process ground truth
  // (eventLoopUtilization + monitorEventLoopDelay) and pass it to the eBPF
  // layer through the same fs.access side channel. The payload is fixed-width:
  // 10 fields x 16 lowercase hex chars, decoded by bpf/generictracer/nodejs.c.
  // Field order: elu_idle_ns, elu_active_ns, delay min/max/mean/stddev/p50/p90/
  // p99 (ns), delay sample count. The histogram is reset after each read so the
  // delay fields are per-interval; ELU values are cumulative since loop start.
  // Fixed, unlike the JVM sampling interval: this script is embedded verbatim,
  // so making it configurable means templating it at injection time.
  const RT_SAMPLING_INTERVAL_MS = 1000;

  if (orig.rtTimer) {
    clearInterval(orig.rtTimer);
  }

  // eventLoopUtilization needs Node 14.10+. Without this guard the interval
  // callback below would throw an uncaught TypeError, which by default
  // terminates the application. Older runtimes simply report no runtime
  // metrics.
  if (typeof performance.eventLoopUtilization === 'function' &&
      typeof monitorEventLoopDelay === 'function') {
    if (!orig.rtHistogram) {
      orig.rtHistogram = monitorEventLoopDelay({ resolution: 10 });
      orig.rtHistogram.enable();
    }

    const rtHex = (v) => {
      const n = Number.isFinite(v) && v > 0 ? Math.round(v) : 0;
      return n.toString(16).padStart(16, '0');
    };

    orig.rtTimer = setInterval(() => {
      const h = orig.rtHistogram;
      const elu = performance.eventLoopUtilization();
      const empty = h.count === 0;
      const fields = [
        elu.idle * 1e6, // eventLoopUtilization reports milliseconds
        elu.active * 1e6,
        empty ? 0 : h.min,
        empty ? 0 : h.max,
        empty ? 0 : h.mean,
        empty ? 0 : h.stddev,
        empty ? 0 : h.percentile(50),
        empty ? 0 : h.percentile(90),
        empty ? 0 : h.percentile(99),
        h.count,
      ];
      h.reset();
      try {
        fs.accessSync(`/dev/null/obi-rt/${fields.map(rtHex).join('')}`);
      } catch (_) {}
    }, RT_SAMPLING_INTERVAL_MS);
    orig.rtTimer.unref();
  }
})()
