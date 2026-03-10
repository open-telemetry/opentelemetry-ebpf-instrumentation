FROM golang:1.25.7@sha256:931c889bca758a82fcbfcb1b6ed6ca1de30783e9e52e6093ad50060735cb99be AS builder

WORKDIR /build

COPY internal/test/integration/components/grpc_relay/go/go.mod .
COPY internal/test/integration/components/grpc_relay/go/main.go .

RUN go mod tidy && go build -o relay .

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /build/relay /relay

ENTRYPOINT ["/relay"]
