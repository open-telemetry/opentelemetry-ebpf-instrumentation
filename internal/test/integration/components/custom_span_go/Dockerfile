# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421 AS libstapsdt-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libelf-dev \
    && rm -rf /var/lib/apt/lists/*

COPY internal/test/integration/components/libstapsdt-arm64/ /libstapsdt/
RUN make -C /libstapsdt all && make -C /libstapsdt install && ldconfig

FROM golang:1.23-bookworm@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db AS go-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        libelf-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so /usr/lib/libstapsdt.so
COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so.0 /usr/lib/libstapsdt.so.0
COPY --from=libstapsdt-builder /usr/include/libstapsdt.h /usr/include/libstapsdt.h
RUN ldconfig

WORKDIR /src
COPY internal/test/integration/components/custom_span_go/go.mod ./go.mod
COPY internal/test/integration/components/custom_span_go/go.sum ./go.sum
COPY internal/test/integration/components/custom_span_go/main.go ./main.go
# -ldflags="-s -w" strips .symtab so OBI must resolve main.processOrder via .gopclntab.
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /custom_span_go .

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

RUN apt-get update && apt-get install -y --no-install-recommends \
        libelf1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so /usr/lib/libstapsdt.so
COPY --from=libstapsdt-builder /usr/lib/libstapsdt.so.0 /usr/lib/libstapsdt.so.0
RUN ldconfig

COPY --from=go-builder /custom_span_go /custom_span_go
EXPOSE 8394
ENTRYPOINT ["/custom_span_go"]
