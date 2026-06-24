FROM node:24-slim@sha256:b31e7a42fdf8b8aa5f5ed477c72d694301273f1069c5a2f71d53c6482e99a2fc

WORKDIR /app

COPY internal/test/integration/components/grpc_relay/nodejs/package.json internal/test/integration/components/grpc_relay/nodejs/package-lock.json ./
RUN npm ci

COPY internal/test/integration/components/grpc_relay/relay.proto .
COPY internal/test/integration/components/grpc_relay/nodejs/server.js .

CMD ["node", "server.js"]
