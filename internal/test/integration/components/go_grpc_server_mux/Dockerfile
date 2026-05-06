# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25.9@sha256:8a7adc288b77e9b787cd2695029eb54d10ae80571b21d44fed68d067ad0a9c96 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY main.go main.go
COPY x509/server_test_cert.pem x509/server_test_cert.pem
COPY x509/server_test_key.pem x509/server_test_key.pem


# Build
RUN go build -o testserver main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
RUN mkdir -p x509
COPY --from=builder /src/testserver .
COPY --from=builder /src/x509/server_test_cert.pem x509
COPY --from=builder /src/x509/server_test_key.pem x509
USER 0:0

CMD [ "/testserver" ]