# Build the tpclient-go binary.
# Mirrors internal/test/integration/components/httppinger/Dockerfile.
FROM golang:1.25.8@sha256:f55a6ec7f24aedc1ed66e2641fdc52de01f2d24d6e49d1fa38582c07dd5f601d AS builder

ARG TARGETARCH
ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY internal/test/ internal/test/
COPY go.mod go.mod
COPY go.sum go.sum

RUN go build -o tpclient-go ./internal/test/integration/components/tpclient-go/main.go

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /src/tpclient-go /usr/local/bin/tpclient-go
COPY internal/test/integration/components/tpclient-go/start-all.sh /usr/local/bin/start-all.sh
RUN chmod +x /usr/local/bin/start-all.sh

USER 0:0
EXPOSE 8000 8001 8002

CMD ["/usr/local/bin/start-all.sh"]
