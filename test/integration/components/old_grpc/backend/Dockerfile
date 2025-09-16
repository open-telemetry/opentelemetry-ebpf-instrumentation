FROM golang:1.25@sha256:8305f5fa8ea63c7b5bc85bd223ccc62941f852318ebfbd22f53bbd0b358c07e1 AS builder

WORKDIR /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/

COPY test/integration/components/old_grpc/worker ./worker
COPY test/integration/components/old_grpc/backend ./backend

WORKDIR /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/backend

RUN make compile

FROM ubuntu:latest@sha256:590e57acc18d58cd25d00254d4ca989bbfcd7d929ca6b521892c9c904c391f50

WORKDIR /
COPY --from=builder /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/backend/bin/backend /backend

ENTRYPOINT ["/backend"]
