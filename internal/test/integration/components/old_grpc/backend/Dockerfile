FROM golang:1.25.3 AS builder

WORKDIR /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/

COPY internal/test/integration/components/old_grpc/worker ./worker
COPY internal/test/integration/components/old_grpc/backend ./backend

WORKDIR /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend

RUN make compile

FROM ubuntu:latest@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252

WORKDIR /
COPY --from=builder /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend/bin/backend /backend

ENTRYPOINT ["/backend"]
