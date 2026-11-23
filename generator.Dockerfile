FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS dist

WORKDIR /src
ENV GOPATH=/go
ENV PATH="/root/.local/bin:/go/bin:${PATH}"

ENV PROTOC_VERSION=32.0
ENV PROTOC_X86_64_SHA256="7ca037bfe5e5cabd4255ccd21dd265f79eb82d3c010117994f5dc81d2140ee88"
ENV PROTOC_AARCH_64_SHA256="56af3fc2e43a0230802e6fadb621d890ba506c5c17a1ae1070f685fe79ba12d0"

ARG TARGETARCH

# Temporary MISE_VERSION override below: remove before merge once the installer selects the required minimum.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl bash git make unzip \
    && rm -rf /var/lib/apt/lists/* \
    && export MISE_VERSION=2026.10.18 \
    && curl -fsSL https://mise.run | sh

COPY mise.toml mise.lock ./
RUN mkdir -p /go/bin && MISE_ENABLE_TOOLS=go,clang,conda:llvm-tools mise install go clang conda:llvm-tools

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
    && MISE_ENABLE_TOOLS=go mise exec -- go build -o /go/bin/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go \
    && MISE_ENABLE_TOOLS=go mise exec -- go build -o /go/bin/protoc-gen-go-grpc google.golang.org/grpc/cmd/protoc-gen-go-grpc \
    && MISE_ENABLE_TOOLS=go mise exec -- go build -o /go/bin/bpf2go github.com/cilium/ebpf/cmd/bpf2go \
    && protoc --version \
    && /go/bin/protoc-gen-go --version \
    && /go/bin/protoc-gen-go-grpc --version

RUN cat <<EOF > /generate.sh
#!/bin/sh
export BPF2GO=/go/bin/bpf2go
export CLANG=clang
export GOCACHE=/tmp/go-build
MISE_ENABLE_TOOLS=go,clang,conda:llvm-tools mise exec -- make -f bpf/Makefile generate
EOF

RUN chmod +x /generate.sh

ENTRYPOINT ["/generate.sh"]
