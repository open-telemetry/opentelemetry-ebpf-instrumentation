# This dockerfile generates the container image that is required to run "make protoc-gen"

# Use an official Golang runtime as a parent image
FROM golang:1.24@sha256:db5d0afbfb4ab648af2393b92e87eaae9ad5e01132803d80caef91b5752d289c

ARG TARGETARCH

# Set environment variables
ENV PROTOC_VERSION=28.2

# Install dependencies
RUN apt-get update && apt-get install -y unzip curl tree

# Install protoc
# Deal with the arm64==aarch64 ambiguity
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        curl -qL https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-aarch_64.zip -o protoc.zip; \
    else \
        curl -qL https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip -o protoc.zip; \
    fi
RUN unzip protoc.zip -d /usr/local
RUN rm protoc.zip

# Install protoc-gen-go
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

# Install protoc-gen-go-grpc
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Verify installations
RUN protoc --version
RUN protoc-gen-go --version
RUN protoc-gen-go-grpc --version

