FROM golang:1.25.0-alpine@sha256:f18a072054848d87a8077455f0ac8a25886f2397f88bfdd222d6fafbb5bba440 AS base
FROM base AS builder

WORKDIR /build

COPY cmd/obi-genfiles/obi_genfiles.go .
COPY go.mod go.mod
COPY go.sum go.sum
RUN go build -o obi_genfiles obi_genfiles.go

FROM base AS dist

WORKDIR /src

ENV EBPF_VER=v0.19.0
ENV PROTOC_VERSION=32.0
ARG TARGETARCH

RUN apk add clang llvm20 wget unzip curl wget
RUN apk cache purge

# Install protoc
# Deal with the arm64==aarch64 ambiguity
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        curl -qL https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-aarch_64.zip -o protoc.zip; \
    else \
        curl -qL https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip -o protoc.zip; \
    fi
RUN unzip protoc.zip -d /usr/local
RUN rm protoc.zip

# Install protoc-gen-go and protoc-gen-go-grpc
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Install eBPF tools
RUN go install github.com/cilium/ebpf/cmd/bpf2go@$EBPF_VER
COPY --from=builder /build/obi_genfiles /go/bin

# Verify installations
RUN protoc --version
RUN protoc-gen-go --version  
RUN protoc-gen-go-grpc --version

RUN cat <<EOF > /generate.sh
#!/bin/sh
export GOCACHE=/tmp
export GOMODCACHE=/tmp/go-mod-cache
export BPF2GO=bpf2go
export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g -Wall -Werror"
export OTEL_EBPF_GENFILES_RUN_LOCALLY=1
export OTEL_EBPF_GENFILES_MODULE_ROOT="/src"
obi_genfiles
EOF

RUN chmod +x /generate.sh

ENTRYPOINT ["/generate.sh"]

