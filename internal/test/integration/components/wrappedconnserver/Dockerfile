FROM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS builder
WORKDIR /src
COPY internal/test/integration/components/wrappedconnserver/main.go .
RUN CGO_ENABLED=0 go build -o /wrappedconnserver main.go

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421
COPY --from=builder /wrappedconnserver /wrappedconnserver
COPY internal/test/integration/components/gohttp2/server/cert.pem /cert.pem
COPY internal/test/integration/components/gohttp2/server/key.pem /key.pem
ENTRYPOINT ["/wrappedconnserver"]
