# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25.5@sha256:6cc2338c038bc20f96ab32848da2b5c0641bb9bb5363f2c33e9b7c8838f9a208 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/ internal/test/
COPY go.mod go.mod
COPY go.sum go.sum

# Build
RUN go build -o testserver ./internal/test/integration/components/testserver/testserver.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:d5d3f9c23164ea16f31852f95bd5959aad1c5e854332fe00f7b3a20fcc9f635c

WORKDIR /
RUN mkdir -p x509
COPY --from=builder /src/testserver .
COPY --from=builder /src/internal/test/integration/components/testserver/x509/server_test_cert.pem x509
COPY --from=builder /src/internal/test/integration/components/testserver/x509/server_test_key.pem x509
USER 0:0

CMD [ "/testserver" ]
