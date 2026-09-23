'use strict';

const fs = require('fs');
const net = require('net');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

const scenario = process.argv[2];
const REQUESTS = 3;
const MICROTASKS = 5;
const MACROTASKS = 3;

const events = [];
const origExists = fs.existsSync;
fs.existsSync = (p, ...rest) => {
  if (typeof p === 'string' && p.startsWith('/dev/null/obi')) {
    events.push(p);
    return false;
  }
  return origExists(p, ...rest);
};

const src = fs
  .readFileSync(path.join(__dirname, '..', 'fdextractor.js'), 'utf8')
  .replace('= false; /*OBI_TRACES_ENABLED*/', '= true; /*OBI_TRACES_ENABLED*/')
  .replace('= false; /*OBI_CTX_HOOK_ENABLED*/', '= true; /*OBI_CTX_HOOK_ENABLED*/');
// eslint-disable-next-line no-eval
eval(src);

const requestFd = () => globalThis[Symbol.for('otel-ebpf-instrumentation.fdextractor')].requestFd();
const macrotask = () => new Promise((r) => setImmediate(r));
const microtask = () => Promise.resolve();

function runClient(code, port, done) {
  const child = spawn(process.execPath, ['-e', code, String(port)], { stdio: 'ignore' });
  child.on('exit', () => setTimeout(done, 20));
}

function finish(server, extra) {
  server.close();
  fs.existsSync = origExists;
  process.stdout.write(JSON.stringify({ events, ...extra }));
}

const keepAliveClient = (connections) => `
  const http = require('http');
  const port = Number(process.argv[1]);
  let pending = ${connections};
  for (let c = 0; c < ${connections}; c++) {
    const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
    let left = ${REQUESTS};
    const next = () => http.get({ host: '127.0.0.1', port, agent, path: '/' }, (res) => {
      res.resume();
      res.on('end', () => {
        if (--left) return next();
        agent.destroy();
        if (--pending === 0) process.exit(0);
      });
    });
    next();
  }`;

function httpScenario(connections, handler) {
  const handlerFds = [];
  const server = http.createServer(async (_req, res) => {
    handlerFds.push(requestFd());
    await handler(res);
    res.end('ok');
  });
  server.listen(0, '127.0.0.1', () => {
    runClient(keepAliveClient(connections), server.address().port, () => finish(server, { handlerFds }));
  });
}

switch (scenario) {
  case 'continuations': {
    httpScenario(1, async () => {
      events.push('start');
      for (let i = 0; i < MICROTASKS; i++) await microtask();
      events.push('microtasks-done');
      for (let i = 0; i < MACROTASKS; i++) await macrotask();
      events.push('macrotasks-done');
    });
    break;
  }
  case 'outgoing-write': {
    const sink = net.createServer((s) => s.resume());
    sink.listen(0, '127.0.0.1', () => {
      const sinkPort = sink.address().port;
      httpScenario(1, async () => {
        const out = net.connect(sinkPort, '127.0.0.1');
        await new Promise((r) => out.once('connect', r));
        events.push('before-write');
        out.write('x');
        events.push('wrote');
        await microtask();
        events.push('after-write');
        out.destroy();
      });
    });
    setTimeout(() => sink.close(), 5000).unref();
    break;
  }
  case 'write-before-connect': {
    const sink = net.createServer((s) => s.resume());
    sink.listen(0, '127.0.0.1', () => {
      const sinkPort = sink.address().port;
      httpScenario(1, async () => {
        const out = net.connect(sinkPort, '127.0.0.1');
        out.once('connect', () => events.push('connect-callback'));
        out.write('x');
        events.push('wrote');
        await new Promise((r) => out.once('connect', r));
        events.push('connected');
        out.destroy();
      });
    });
    setTimeout(() => sink.close(), 5000).unref();
    break;
  }
  case 'interleave': {
    httpScenario(2, async () => {
      for (let i = 0; i < MACROTASKS; i++) {
        await macrotask();
        events.push(`handler:${requestFd()}`);
        await microtask();
        events.push(`handler:${requestFd()}`);
      }
    });
    break;
  }
  case 'raw-tcp': {
    const server = net.createServer(async (sock) => {
      await macrotask();
      events.push('start');
      for (let i = 0; i < MICROTASKS; i++) await microtask();
      events.push('microtasks-done');
      for (let i = 0; i < REQUESTS; i++) {
        await macrotask();
        events.push('handler');
      }
      sock.end('ok');
    });
    server.listen(0, '127.0.0.1', () => {
      const client = `
        const net = require('net');
        const sock = net.connect(Number(process.argv[1]), '127.0.0.1');
        sock.resume();`;
      runClient(client, server.address().port, () => finish(server, {}));
    });
    break;
  }
  default:
    throw new Error('unknown scenario: ' + scenario);
}
