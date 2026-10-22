# Build the legacy x/net HTTP/2 test client.
FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY internal/test/integration/components/gohttp2/client_xnet_legacy/go.mod ./go.mod
COPY internal/test/integration/components/gohttp2/client_xnet_legacy/go.sum ./go.sum
COPY internal/test/integration/components/gohttp2/client/*.go ./

RUN go build -tags legacy_xnet -o /http2client .

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /http2client .
USER 0:0

CMD [ "/http2client" ]
