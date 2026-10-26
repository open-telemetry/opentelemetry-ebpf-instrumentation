FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS builder

WORKDIR /build

COPY internal/test/integration/components/grpc_relay/go/ .

RUN go mod download && go build -o relay .

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /build/relay /relay
COPY internal/test/integration/components/testserver/x509/server_test_cert.pem /server_test_cert.pem
COPY internal/test/integration/components/testserver/x509/server_test_key.pem /server_test_key.pem

ENTRYPOINT ["/relay"]
