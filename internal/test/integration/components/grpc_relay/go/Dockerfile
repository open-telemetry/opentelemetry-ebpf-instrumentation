FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

WORKDIR /build

COPY internal/test/integration/components/grpc_relay/go/ .

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod go mod download && go build -o relay .

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /build/relay /relay
COPY internal/test/integration/components/testserver/x509/server_test_cert.pem /server_test_cert.pem
COPY internal/test/integration/components/testserver/x509/server_test_key.pem /server_test_key.pem

ENTRYPOINT ["/relay"]
