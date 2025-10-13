FROM golang:1.25@sha256:1c91b4f4391774a73d6489576878ad3ff3161ebc8c78466ec26e83474855bfcf AS builder

WORKDIR /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/

COPY test/integration/components/old_grpc/worker ./worker
COPY test/integration/components/old_grpc/backend ./backend

WORKDIR /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/backend

RUN make compile

FROM ubuntu:latest@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252

WORKDIR /
COPY --from=builder /src/go.opentelemetry.io/obi/test/integration/components/old_grpc/backend/bin/backend /backend

ENTRYPOINT ["/backend"]
