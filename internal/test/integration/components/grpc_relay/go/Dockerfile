FROM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS builder

WORKDIR /build

COPY internal/test/integration/components/grpc_relay/go/ .

RUN go mod download && go build -o relay .

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /build/relay /relay

ENTRYPOINT ["/relay"]
