FROM golang:1.25.10@sha256:315d6d304226d0180a011ead57af82c9fe16f84fcf0eaa17d11034a53f63fbc4 AS builder

WORKDIR /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/

COPY internal/test/integration/components/old_grpc/worker ./worker
COPY internal/test/integration/components/old_grpc/backend ./backend

WORKDIR /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend

RUN make compile

FROM ubuntu:noble-20251013@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

WORKDIR /
COPY --from=builder /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend/bin/backend /backend

ENTRYPOINT ["/backend"]
