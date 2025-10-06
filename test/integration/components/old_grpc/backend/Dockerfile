FROM golang:1.25@sha256:d7098379b7da665ab25b99795465ec320b1ca9d4addb9f77409c4827dc904211 AS builder

WORKDIR /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/

COPY test/integration/components/old_grpc/worker ./worker
COPY test/integration/components/old_grpc/backend ./backend

WORKDIR /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/backend

RUN make compile

FROM ubuntu:latest@sha256:728785b59223d755e3e5c5af178fab1be7031f3522c5ccd7a0b32b80d8248123

WORKDIR /
COPY --from=builder /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/backend/bin/backend /backend

ENTRYPOINT ["/backend"]
