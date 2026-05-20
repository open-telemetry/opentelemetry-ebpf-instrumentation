FROM node:24-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d

WORKDIR /app

COPY internal/test/integration/components/grpc_relay/nodejs/package.json internal/test/integration/components/grpc_relay/nodejs/package-lock.json ./
RUN npm ci

COPY internal/test/integration/components/grpc_relay/relay.proto .
COPY internal/test/integration/components/grpc_relay/nodejs/server.js .

CMD ["node", "server.js"]
