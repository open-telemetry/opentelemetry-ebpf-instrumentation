FROM golang:1.25.8@sha256:f55a6ec7f24aedc1ed66e2641fdc52de01f2d24d6e49d1fa38582c07dd5f601d AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY go.mod go.mod
COPY go.sum go.sum
COPY examples/go-channel-links/app examples/go-channel-links/app

RUN go build -o /out/channel-links-app ./examples/go-channel-links/app

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /out/channel-links-app /channel-links-app

EXPOSE 8080

CMD ["/channel-links-app"]
