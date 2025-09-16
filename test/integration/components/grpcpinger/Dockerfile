# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25@sha256:8305f5fa8ea63c7b5bc85bd223ccc62941f852318ebfbd22f53bbd0b358c07e1 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY test/ test/
COPY go.mod go.mod
COPY go.sum go.sum

# Build
RUN go build -o grpcpinger ./test/integration/components/grpcpinger/grpcpinger.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:df52e55e3361a81ac1bead266f3373ee55d29aa50cf0975d440c2be3483d8ed3

WORKDIR /
COPY --from=builder /src/grpcpinger .
USER 0:0

CMD [ "/grpcpinger" ]
