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
http.createServer((req, res) => {
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
