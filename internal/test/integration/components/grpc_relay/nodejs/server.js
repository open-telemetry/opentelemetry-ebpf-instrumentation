const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const http = require('http');
const path = require('path');

const PROTO_PATH = path.join(__dirname, 'relay.proto');
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});
const relayProto = grpc.loadPackageDefinition(packageDefinition).relay;

const nextHop = process.env.NEXT_HOP || '';
const grpcPort = process.env.GRPC_PORT || '50053';
const healthPort = process.env.HEALTH_PORT || '8092';

// Persistent client — reuses the same HTTP/2 connection across requests.
let client = null;
if (nextHop) {
  client = new relayProto.Relay(nextHop, grpc.credentials.createInsecure());
}

function relay(call, callback) {
  console.log('received Relay RPC');
  if (client) {
    client.Relay({}, (err, response) => {
      if (err) {
        callback(err);
      } else {
        callback(null, response || {});
      }
    });
  } else {
    callback(null, {});
  }
}

const server = new grpc.Server();
server.addService(relayProto.Relay.service, { Relay: relay });
server.bindAsync(
  `0.0.0.0:${grpcPort}`,
  grpc.ServerCredentials.createInsecure(),
  (err, port) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    server.start();
    console.log(`gRPC listening on :${port}`);
  }
);

// /multiplexed fans out N concurrent gRPC calls on the persistent client
// to exercise sk_msg HPACK injection on multiplexed HTTP/2 streams
const MULTIPLEX_N = 3;

// /self-prop?tp=<traceparent>&n=<calls>: sets traceparent metadata like an SDK, on its own
// channel so OBI's stand-down on that socket cannot mask the persistent client. A fresh
// channel per request keeps the first call's field a literal on every test retry; the calls
// within one request still share it, so nghttp2 indexes the field and later calls send a
// single index byte, with nothing left on the wire for OBI to find.
function selfProp(req, res) {
  const params = new URL(req.url, 'http://localhost').searchParams;
  const tp = params.get('tp');
  if (!tp) {
    res.writeHead(400);
    res.end();
    return;
  }
  const calls = Math.max(1, Number(params.get('n')) || 3);
  const meta = new grpc.Metadata();
  meta.set('traceparent', tp);

  const selfPropClient = new relayProto.Relay(nextHop, grpc.credentials.createInsecure(), {
    'grpc.primary_user_agent': 'self-prop',
  });

  let pending = calls;
  const done = () => {
    if (--pending === 0) {
      selfPropClient.close();
      res.writeHead(200);
      res.end();
    }
  };
  for (let i = 0; i < calls; i++) {
    selfPropClient.Relay({}, meta, done);
  }
}

http.createServer((req, res) => {
  if (req.url.startsWith('/self-prop')) {
    if (!nextHop) {
      res.writeHead(503);
      res.end();
      return;
    }
    selfProp(req, res);
    return;
  }
  if (req.url !== '/multiplexed' || !client) {
    res.writeHead(200);
    res.end();
    return;
  }
  let pending = MULTIPLEX_N;
  for (let i = 0; i < MULTIPLEX_N; i++) {
    client.Relay({}, () => {
      if (--pending === 0) {
        res.writeHead(200);
        res.end();
      }
    });
  }
}).listen(healthPort, () => {
  console.log(`health listening on :${healthPort}`);
});
