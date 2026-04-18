# Build the testserver binary
# Docker command must be invoked from the projec root directory
# Make sure that the Go version here is a minor number less than in the Dockerfile_latest file
# in this same folder.
# This way we make sure that we support any internal compiler changes in newer Go versions
FROM golang:1.25.8@sha256:f55a6ec7f24aedc1ed66e2641fdc52de01f2d24d6e49d1fa38582c07dd5f601d AS builder

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
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
RUN mkdir -p x509
COPY --from=builder /src/testserver .
COPY --from=builder /src/internal/test/integration/components/testserver/x509/server_test_cert.pem x509
COPY --from=builder /src/internal/test/integration/components/testserver/x509/server_test_key.pem x509
USER 0:0

CMD [ "/testserver" ]
