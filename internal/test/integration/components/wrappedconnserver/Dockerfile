FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder
WORKDIR /src
COPY internal/test/integration/components/wrappedconnserver/main.go .
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod CGO_ENABLED=0 go build -o /wrappedconnserver main.go

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421
COPY --from=builder /wrappedconnserver /wrappedconnserver
COPY internal/test/integration/components/gohttp2/server/cert.pem /cert.pem
COPY internal/test/integration/components/gohttp2/server/key.pem /key.pem
ENTRYPOINT ["/wrappedconnserver"]
