FROM golang:1.25@sha256:8305f5fa8ea63c7b5bc85bd223ccc62941f852318ebfbd22f53bbd0b358c07e1 AS builder

WORKDIR /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/

COPY test/integration/components/old_grpc/worker ./worker
COPY test/integration/components/old_grpc/backend ./backend

WORKDIR /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/backend

RUN make compile

FROM ubuntu:latest@sha256:353675e2a41babd526e2b837d7ec780c2a05bca0164f7ea5dbbd433d21d166fc

WORKDIR /
COPY --from=builder /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/backend/bin/backend /backend

ENTRYPOINT ["/backend"]
