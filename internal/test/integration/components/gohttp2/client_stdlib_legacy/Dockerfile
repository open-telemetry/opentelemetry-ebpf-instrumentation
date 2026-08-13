# Build the Go 1.17 stdlib testclient binary
FROM golang:1.17.13@sha256:87262e4a4c7db56158a80a18fefdc4fee5accc41b59cde821e691d05541bbb18 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY internal/test/integration/components/gohttp2/client_stdlib_legacy/go.mod ./go.mod
COPY internal/test/integration/components/gohttp2/client/*.go ./

RUN go build -tags legacy_stdlib -o /http2client .

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /http2client .
USER 0:0

CMD [ "/http2client" ]
