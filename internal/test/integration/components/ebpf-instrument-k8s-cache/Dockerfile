# Development version of the beyla Dockerfile that compiles for coverage
# and allows retrieving coverage files.
# The production-ready minimal image is in the project root's dockerfile.
FROM golang:1.25@sha256:1a13867f40c6ba8c3e7c07ab5fa921cb58cf8402bcbe452f4d41cd614655e700 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY .git/ .git/
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile

# Build
RUN make compile-cache-for-coverage

# Create final image from minimal + built binary
FROM scratch

WORKDIR /
COPY --from=builder /src/bin/k8s-cache .

ENTRYPOINT [ "/k8s-cache" ]
