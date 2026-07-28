// Deno trace-context propagation agent.
//
// This is the Deno counterpart of fdextractor.js. It cannot reuse the Node
// approach for two reasons discovered empirically against the Deno runtime:
//
//   1. Deno exposes no socket file descriptor to JS (`socket._handle.fd` is
//      undefined), so the fd-pair correlation used for Node is impossible.
//      Instead we correlate connections by their 4-tuple (address + port),
//      which is exactly what the eBPF layer already uses to key server traces.
//
//   2. Deno has no libuv, so the `uv_fs_access` uprobe never attaches. The
//      eBPF signal is delivered by `fs.accessSync()` on a magic path, which in
//      Deno issues a `statx(2)` syscall that a dedicated kprobe parses.
//
// Additionally, Deno's node:net AsyncLocalStorage context does NOT propagate
// from the TCP 'connection' event to request handling, but it DOES propagate
// when established at the HTTP 'request' layer (and from a Deno.serve handler).
// So we install the incoming context at the HTTP layer and read it back when an
// outgoing connection is established via node:net.
//
// Known limitation: outgoing calls made through Deno's native `fetch()` are not
// correlated, because native fetch is implemented entirely in Rust and never
// surfaces a node:net socket (nor its local ephemeral tuple) to JS.

(async ()=> {
  const STORE = Symbol.for('otel-ebpf-instrumentation.fdextractor_deno');
  const LAST_SERVER = Symbol.for('otel-ebpf-instrumentation.deno_last_server');

  const net = await import('net');
  const http = await import('http');
  const https = await import('https');
  const fs = await import('fs');
  const {AsyncLocalStorage} = await import('async_hooks');

  const debug_enabled = false;

  if (!global[STORE]) {
    global[STORE] = {
      serverEmit: {
        http: http.Server.prototype.emit,
        https: https.Server.prototype.emit,
      },
      socketConnect: net.Socket.prototype.connect,
      socketWrite: net.Socket.prototype.write,
      denoServe: (typeof globalThis.Deno !== 'undefined') ? globalThis.Deno.serve : undefined,
    };
  }

  const orig = global[STORE];

// Restore originals first so repeated injection does not stack wrappers.
  http.Server.prototype.emit = orig.serverEmit.http;
  https.Server.prototype.emit = orig.serverEmit.https;
  net.Socket.prototype.connect = orig.socketConnect;
  net.Socket.prototype.write = orig.socketWrite;
  if (orig.denoServe) {
    globalThis.Deno.serve = orig.denoServe;
  }

  if (debug_enabled) {
    console.log('OpenTelemetry eBPF Instrumentation has injected Deno trace-context propagation via the debugger');
    console.log('The debugger will be deactivated again and closed');
  }

// ALS store holds only the incoming server connection's 4-tuple (serverPart).
  const als = new AsyncLocalStorage();

// --- magic-path encoding -------------------------------------------------
//
// A connection endpoint is encoded as 36 lowercase-hex characters: a 16-byte
// address (IPv6, with IPv4 stored as a v4-in-v6 mapped address exactly like the
// eBPF connection_info) followed by a 2-byte port. The signal path is:
//
//   /dev/null/obi-dn/<clientPart><serverPart>
//
// where clientPart is the outgoing connection's local ephemeral endpoint and
// serverPart is the incoming request's remote (client) endpoint.
  const PREFIX = '/dev/null/obi-dn/';

  function hex2(n) {
    return (n & 0xff).toString(16).padStart(2, '0');
  }

  function expandIPv6(host) {
    // Handle a v4-mapped tail, e.g. "::ffff:127.0.0.1".
    let v4tail = null;
    const lastColon = host.lastIndexOf(':');
    const tail = host.slice(lastColon + 1);
    if (tail.indexOf('.') >= 0) {
      v4tail = tail.split('.').map((x) => +x);
      host = host.slice(0, lastColon + 1) + '0:0';
    }
    const halves = host.split('::');
    const head = halves[0] ? halves[0].split(':') : [];
    const tailWords = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
    const words = new Array(8).fill(0);
    for (let i = 0; i < head.length; i++) {
      words[i] = parseInt(head[i], 16) || 0;
    }
    for (let i = 0; i < tailWords.length; i++) {
      words[8 - tailWords.length + i] = parseInt(tailWords[i], 16) || 0;
    }
    const bytes = new Array(16).fill(0);
    for (let i = 0; i < 8; i++) {
      bytes[i * 2] = (words[i] >> 8) & 0xff;
      bytes[i * 2 + 1] = words[i] & 0xff;
    }
    if (v4tail) {
      bytes[12] = v4tail[0];
      bytes[13] = v4tail[1];
      bytes[14] = v4tail[2];
      bytes[15] = v4tail[3];
    }
    return bytes;
  }

  function addrBytes(host, family) {
    const bytes = new Array(16).fill(0);
    if (!host) {
      return bytes;
    }
    if (family === 'IPv6' || host.indexOf(':') >= 0) {
      return expandIPv6(host);
    }
    // IPv4 stored as ::ffff:a.b.c.d to match the eBPF connection_info encoding.
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    const octets = host.split('.');
    bytes[12] = +octets[0];
    bytes[13] = +octets[1];
    bytes[14] = +octets[2];
    bytes[15] = +octets[3];
    return bytes;
  }

  function partHex(host, port, family) {
    const addr = addrBytes(host, family).map(hex2).join('');
    const portHex = (port & 0xffff).toString(16).padStart(4, '0');
    return addr + portHex;
  }

  function signal(clientHost, clientPort, clientFamily, serverPart) {
    const path =
        PREFIX +
        partHex(clientHost, clientPort, clientFamily) +
        partHex(serverPart.host, serverPart.port, serverPart.family);

    if (debug_enabled) {
      console.log(`[deno correlate] ${path}`);
    }

    try {
      fs.accessSync(path);
    } catch (err) {
      // expected: the path never exists; the syscall is the signal.
    }
  }

  function familyOf(host, fallback) {
    if (host && host.indexOf(':') >= 0) {
      return 'IPv6';
    }
    return fallback || 'IPv4';
  }

// --- incoming context: node:http / node:https ----------------------------
  function wrapServerEmit(originalEmit) {
    return function (event, ...args) {
      if (event === 'request') {
        const req = args[0];
        const sock = req && (req.socket || req.connection);
        let serverPart = null;
        if (sock && sock.remoteAddress) {
          serverPart = {
            host: sock.remoteAddress,
            port: sock.remotePort,
            family: familyOf(sock.remoteAddress, sock.remoteFamily),
          };
        }
        if (serverPart) {
          return als.run({serverPart}, () => originalEmit.call(this, event, ...args));
        }
      }
      return originalEmit.call(this, event, ...args);
    };
  }

  http.Server.prototype.emit = wrapServerEmit(orig.serverEmit.http);
  https.Server.prototype.emit = wrapServerEmit(orig.serverEmit.https);

// --- incoming context: Deno.serve -----------------------------------------
  if (orig.denoServe) {
    const wrapHandler = (handler) =>
        function (req, info) {
          const ra = info && info.remoteAddr;
          let serverPart = null;
          if (ra && ra.hostname) {
            serverPart = {
              host: ra.hostname,
              port: ra.port,
              family: familyOf(ra.hostname),
            };
          }
          if (serverPart) {
            return als.run({serverPart}, () => handler(req, info));
          }
          return handler(req, info);
        };

    globalThis.Deno.serve = function (arg1, arg2) {
      if (typeof arg1 === 'function') {
        return orig.denoServe.call(this, wrapHandler(arg1));
      }
      if (arg1 && typeof arg1.handler === 'function') {
        const opts = Object.assign({}, arg1);
        opts.handler = wrapHandler(arg1.handler);
        return orig.denoServe.call(this, opts, arg2);
      }
      if (typeof arg2 === 'function') {
        return orig.denoServe.call(this, arg1, wrapHandler(arg2));
      }
      return orig.denoServe.apply(this, arguments);
    };
  }

// --- outgoing correlation: node:net ---------------------------------------
  function serverPartKey(part) {
    return part.host + '/' + part.port;
  }

  function signalOutgoing(sock, store) {
    if (!store || !store.serverPart) {
      return;
    }
    // A keep-alive socket is reused across incoming requests that may belong to
    // different traces. Re-signal whenever the associated server endpoint
    // changes so the eBPF map points the outgoing connection at the current
    // parent instead of staying pinned to the first request's trace.
    const key = serverPartKey(store.serverPart);
    if (sock[LAST_SERVER] === key) {
      return;
    }
    const name = {};
    try {
      sock._handle.getsockname(name);
    } catch (err) {
      return;
    }
    if (!name.address) {
      return;
    }
    sock[LAST_SERVER] = key;
    signal(name.address, name.port, familyOf(name.address, name.family), store.serverPart);
  }

  net.Socket.prototype.connect = function (...args) {
    const store = als.getStore();
    const sock = this;
    const result = orig.socketConnect.apply(this, args);

    if (store && store.serverPart) {
      sock.once('connect', () => signalOutgoing(sock, store));
    }

    return result;
  };

  net.Socket.prototype.write = function (data, ...rest) {
    const doWrite = () => orig.socketWrite.apply(this, [data, ...rest]);

    if (this === process.stdout || this === process.stderr) {
      return doWrite();
    }

    // Fallback for reused (keep-alive) sockets where 'connect' did not fire in
    // the current async context.
    const store = als.getStore();
    if (store && store.serverPart) {
      signalOutgoing(this, store);
    }

    return doWrite();
  };
})();