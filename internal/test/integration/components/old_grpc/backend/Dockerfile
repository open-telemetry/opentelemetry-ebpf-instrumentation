FROM golang:1.25.11@sha256:00feed335fe561979f2cdcc30a5191231977c5631fe79c40f7d3ab63b4fa222f AS builder

WORKDIR /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/

COPY internal/test/integration/components/old_grpc/worker ./worker
COPY internal/test/integration/components/old_grpc/backend ./backend

WORKDIR /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend

RUN make compile

FROM ubuntu:noble-20251013@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

WORKDIR /
COPY --from=builder /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend/bin/backend /backend

ENTRYPOINT ["/backend"]
