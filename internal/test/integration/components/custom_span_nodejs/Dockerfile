# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Stage 1: build libstapsdt from the locally-vendored arm64-capable fork.
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421 AS libstapsdt-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libelf-dev \
    && rm -rf /var/lib/apt/lists/*

COPY internal/test/integration/components/libstapsdt-arm64/ /libstapsdt/
RUN make -C /libstapsdt all && make -C /libstapsdt install && ldconfig

# Stage 2: install npm deps and compile the Node-API addon against libstapsdt.
FROM node:22-bookworm@sha256:c601a46abb4d2ab80a9dc3da208d50d1122642d53f17a101926ace71e5a9bf1c AS node-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ make python3 libelf-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so /usr/lib/libstapsdt.so
COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so.0 /usr/lib/libstapsdt.so.0
COPY --from=libstapsdt-builder /usr/include/libstapsdt.h /usr/include/libstapsdt.h
RUN ldconfig

WORKDIR /src
COPY internal/test/integration/components/custom_span_nodejs/package.json ./package.json
COPY internal/test/integration/components/custom_span_nodejs/package-lock.json ./package-lock.json
RUN npm ci --ignore-scripts

COPY internal/test/integration/components/custom_span_nodejs/binding.gyp ./binding.gyp
COPY internal/test/integration/components/custom_span_nodejs/binding.cc ./binding.cc
RUN ./node_modules/.bin/node-gyp configure build

FROM node:22-bookworm@sha256:c601a46abb4d2ab80a9dc3da208d50d1122642d53f17a101926ace71e5a9bf1c

RUN apt-get update && apt-get install -y --no-install-recommends \
        libelf1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so /usr/lib/libstapsdt.so
COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so.0 /usr/lib/libstapsdt.so.0
RUN ldconfig

WORKDIR /app
COPY --from=node-builder /src/build /app/build
COPY internal/test/integration/components/custom_span_nodejs/app.js /app/app.js
EXPOSE 8396
ENTRYPOINT ["node", "/app/app.js"]
