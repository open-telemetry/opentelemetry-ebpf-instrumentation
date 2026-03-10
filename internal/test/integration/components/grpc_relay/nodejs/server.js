const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
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
    console.log(`gRPC listening on :${port}`);
  }
);
