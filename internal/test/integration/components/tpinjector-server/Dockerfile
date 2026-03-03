FROM golang:1.26.0@sha256:fb612b7831d53a89cbc0aaa7855b69ad7b0caf603715860cf538df854d047b84 AS builder

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
