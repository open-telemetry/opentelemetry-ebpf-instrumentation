FROM node:20-slim@sha256:d8a35d586fad3af7abb6fdb9ba972388395405f4d462da9e4a4ddcde67b5e0fb

WORKDIR /app

COPY internal/test/integration/components/grpc_relay/nodejs/package.json internal/test/integration/components/grpc_relay/nodejs/package-lock.json ./
RUN npm ci

COPY internal/test/integration/components/grpc_relay/relay.proto .
COPY internal/test/integration/components/grpc_relay/nodejs/server.js .

CMD ["node", "server.js"]
