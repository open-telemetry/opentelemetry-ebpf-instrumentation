FROM golang:1.26.3@sha256:efaccb5b497e90df3ebe5216cc25cd9f98e73874e2d638b56e38d4a3f098c41c AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY internal/test/ internal/test/
COPY go.mod go.mod
COPY go.sum go.sum

RUN go build -o keepaliveclient ./internal/test/integration/components/keepaliveclient/

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /

COPY --from=builder /src/keepaliveclient .
USER 0:0

HEALTHCHECK --interval=1s --retries=15 CMD test -f /tmp/connected

CMD [ "/keepaliveclient" ]
