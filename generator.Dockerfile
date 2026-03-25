FROM golang:1.25.8-alpine@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa AS base
FROM base AS dist

WORKDIR /src

ENV PROTOC_VERSION=32.0
ENV PROTOC_X86_64_SHA256="7ca037bfe5e5cabd4255ccd21dd265f79eb82d3c010117994f5dc81d2140ee88"
ENV PROTOC_AARCH_64_SHA256="56af3fc2e43a0230802e6fadb621d890ba506c5c17a1ae1070f685fe79ba12d0"

ARG TARGETARCH

RUN apk add clang llvm20 wget unzip curl make bash git
RUN apk cache purge

COPY internal/tools/generator/ internal/tools/generator/

# Install protoc
# Deal with the arm64==aarch64 ambiguity
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        curl -qL https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-aarch_64.zip -o protoc.zip; \
        echo "${PROTOC_AARCH_64_SHA256}  protoc.zip" > protoc.zip.sha256 ; \
    else \
        curl -qL https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip -o protoc.zip; \
        echo "${PROTOC_X86_64_SHA256}  protoc.zip" > protoc.zip.sha256 ; \
    fi; \
    sha256sum -c protoc.zip.sha256 \
    && unzip protoc.zip -d /usr/local \
    && rm protoc.zip

# Install protoc-gen-go, protoc-gen-go-grpc, and eBPF tools.
RUN --mount=type=cache,target=/go/pkg \
    cd internal/tools/generator \
    && go build -o /go/bin/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go \
    && go build -o /go/bin/protoc-gen-go-grpc google.golang.org/grpc/cmd/protoc-gen-go-grpc \
    && go build -o /go/bin/bpf2go github.com/cilium/ebpf/cmd/bpf2go \
    && protoc --version \
    && /go/bin/protoc-gen-go --version \
    && /go/bin/protoc-gen-go-grpc --version

RUN cat <<EOF > /generate.sh
#!/bin/sh
export PATH="/usr/lib/llvm20/bin:\$PATH"
export BPF2GO=/go/bin/bpf2go
export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g -Wall -Werror"
export GOCACHE=/tmp/go-build
make generate
EOF

RUN chmod +x /generate.sh

ENTRYPOINT ["/generate.sh"]
