# Build the legacy x/net HTTP/2 test client.
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY internal/test/integration/components/gohttp2/client_xnet_legacy/go.mod ./go.mod
COPY internal/test/integration/components/gohttp2/client_xnet_legacy/go.sum ./go.sum
COPY internal/test/integration/components/gohttp2/client/*.go ./

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod go build -tags legacy_xnet -o /http2client .

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /http2client .
USER 0:0

CMD [ "/http2client" ]
