FROM golang:1.26.3@sha256:313faae491b410a35402c05d35e7518ae99103d957308e940e1ae2cfa0aac29b AS builder

WORKDIR /build

COPY internal/test/integration/components/grpc_relay/go/ .

RUN go mod download && go build -o relay .

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /build/relay /relay

ENTRYPOINT ["/relay"]
