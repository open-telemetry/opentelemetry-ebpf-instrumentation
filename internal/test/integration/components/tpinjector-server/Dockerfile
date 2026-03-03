FROM golang:1.25.7@sha256:931c889bca758a82fcbfcb1b6ed6ca1de30783e9e52e6093ad50060735cb99be AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY internal/test/ internal/test/
COPY go.mod go.mod
COPY go.sum go.sum

RUN go build -o tpinjector-server ./internal/test/integration/components/tpinjector-server/

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /

COPY --from=builder /src/tpinjector-server .
USER 0:0

CMD [ "/tpinjector-server" ]
