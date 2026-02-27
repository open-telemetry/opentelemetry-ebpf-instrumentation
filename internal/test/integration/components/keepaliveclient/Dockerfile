FROM golang:1.25.7@sha256:85c0ab0b73087fda36bf8692efe2cf67c54a06d7ca3b49c489bbff98c9954d64 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY internal/test/ internal/test/
COPY go.mod go.mod
COPY go.sum go.sum

RUN go build -o keepaliveclient ./internal/test/integration/components/keepaliveclient/

FROM debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe

WORKDIR /

COPY --from=builder /src/keepaliveclient .
USER 0:0

HEALTHCHECK --interval=1s --retries=15 CMD test -f /tmp/connected

CMD [ "/keepaliveclient" ]
