FROM golang:1.25.5@sha256:20b91eda7a9627c127c0225b0d4e8ec927b476fa4130c6760928b849d769c149 AS builder

WORKDIR /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/

COPY internal/test/integration/components/old_grpc/worker ./worker
COPY internal/test/integration/components/old_grpc/backend ./backend

WORKDIR /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend

RUN make compile

FROM ubuntu:latest@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

WORKDIR /
COPY --from=builder /src/go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend/bin/backend /backend

ENTRYPOINT ["/backend"]
