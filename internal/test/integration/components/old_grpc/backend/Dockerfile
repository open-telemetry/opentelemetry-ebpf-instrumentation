FROM golang:1.25.8@sha256:f55a6ec7f24aedc1ed66e2641fdc52de01f2d24d6e49d1fa38582c07dd5f601d AS builder

WORKDIR /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/

COPY internal/test/integration/components/old_grpc/worker ./worker
COPY internal/test/integration/components/old_grpc/backend ./backend

WORKDIR /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend

RUN make compile

FROM ubuntu:noble-20251013@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

WORKDIR /
COPY --from=builder /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend/bin/backend /backend

ENTRYPOINT ["/backend"]
