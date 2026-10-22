ARG GENERATOR_BASE=ghcr.io/open-telemetry/obi-generator:0.2.17@sha256:1ae9406f2566e32ccf5d8ba8e5ff0586a322300ae82870988ad605429021174a

# Build JNI native library using Go image (has gcc, no apt install needed)
FROM golang:1.27.2@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS jni-builder
ARG BUILDARCH=amd64
COPY --from=gradle:9.8.1-jdk21-noble@sha256:d879477a2197b2b8a5eb910d007f0b1594eb440aa2740baac17ea245fcfb02f7 /opt/java/openjdk/include /opt/java/include
WORKDIR /build
COPY pkg/internal/java/agent/src/main/c/ src/main/c/
COPY pkg/internal/java/agent/build-jni.sh build-jni.sh

# Install the cross compile toolchain
RUN apt update
RUN case "$BUILDARCH" in \
      amd64) CROSS_CC_PKG=gcc-aarch64-linux-gnu ;; \
      arm64) CROSS_CC_PKG=gcc-x86-64-linux-gnu ;; \
      *)     CC=gcc ;; \
    esac && \
    apt-get install $CROSS_CC_PKG -y

# Own architecture
RUN case "$BUILDARCH" in \
      amd64) SLUG=linux-amd64 ;; \
      arm64) SLUG=linux-aarch64 ;; \
      *)     CC=gcc ;; \
    esac && \
    CC=gcc JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR=build/jni/$SLUG TARGET_DIR=target/classes/native/$SLUG ./build-jni.sh

# Cross-compile the other
RUN case "$BUILDARCH" in \
      amd64) CC=aarch64-linux-gnu-gcc \
             SLUG=linux-aarch64 ;; \
      arm64) CC=x86_64-linux-gnu-gcc \
             SLUG=linux-amd64 ;; \
      *)     CC=gcc ;; \
    esac && \
    JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR=build/jni/$SLUG TARGET_DIR=target/classes/native/$SLUG ./build-jni.sh

# Build the Java OBI agent
FROM gradle:9.8.1-jdk21-noble@sha256:d879477a2197b2b8a5eb910d007f0b1594eb440aa2740baac17ea245fcfb02f7 AS javaagent-builder

WORKDIR /build

# Copy build files
COPY pkg/internal/java .

# Pre-built native library from jni-builder stage
COPY --from=jni-builder /build/target/classes/native/linux-amd64/libobijni.so agent/target/classes/native/linux-amd64/libobijni.so
COPY --from=jni-builder /build/target/classes/native/linux-aarch64/libobijni.so agent/target/classes/native/linux-aarch64/libobijni.so

# Build the project (skip native lib compilation, already done above)
RUN gradle build -x buildNativeLib-amd64 -x buildNativeLib-aarch64 --no-daemon

# Build the autoinstrumenter binary
FROM ${GENERATOR_BASE} AS builder

ARG TARGETARCH
ARG RELEASE_VERSION=unset
ARG RELEASE_REVISION=unset

ENV GOARCH=$TARGETARCH

WORKDIR /src

ENV CLANG=clang
ENV BPF2GO=/go/bin/bpf2go

COPY go.mod go.sum mise.toml mise.lock ./
# Cache module cache.
RUN --mount=type=cache,target=/go/pkg/mod MISE_ENABLE_TOOLS=go mise exec -- go mod download

COPY bpf/ bpf/
COPY cmd/ cmd/
COPY internal/goabi/ internal/goabi/
COPY internal/goversion/ internal/goversion/
COPY internal/config/ internal/config/
COPY pkg/ pkg/
COPY --from=javaagent-builder /build/build/obi-java-agent.jar /src/pkg/internal/java/embedded/obi-java-agent.jar

# Build
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
	MISE_ENABLE_TOOLS=go,clang,conda:llvm-tools mise exec -- make -f bpf/Makefile generate \
	&& mkdir -p bin \
	&& MISE_ENABLE_TOOLS=go mise exec -- env CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build \
	  -ldflags="-X 'go.opentelemetry.io/obi/pkg/buildinfo.Version=${RELEASE_VERSION}' -X 'go.opentelemetry.io/obi/pkg/buildinfo.Revision=${RELEASE_REVISION}'" \
	  -o bin/obi cmd/obi/main.go

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="The OpenTelemetry Authors"

WORKDIR /

COPY --from=builder /src/bin/obi .
COPY LICENSE NOTICE ./
COPY NOTICES ./NOTICES

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/obi" ]
