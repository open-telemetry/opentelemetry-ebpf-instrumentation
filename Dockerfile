ARG TAG=0.2.15@sha256:9cbb1b567377d5779b04e6bcdb87431c77a19e797b4630eba30f5417de96ea33

# Build JNI native library using Go image (has gcc, no apt install needed)
FROM golang:1.26.4@sha256:f96cc555eb8db430159a3aa6797cd5bae561945b7b0fe7d0e284c63a3b291609 AS jni-builder
ARG BUILDARCH=amd64
COPY --from=gradle:9.6.1-jdk21-noble@sha256:79b27b5ea2d30a9e2d044098b7bd83bc15d22611166cb88eecf11a6501484c82 /opt/java/openjdk/include /opt/java/include
WORKDIR /build
COPY pkg/internal/java/agent/src/main/c/ src/main/c/
COPY pkg/internal/java/agent/Makefile.jni Makefile.jni

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
    make -f Makefile.jni CC=gcc JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR=build/jni/$SLUG TARGET_DIR=target/classes/native/$SLUG

# Cross-compile the other
RUN case "$BUILDARCH" in \
      amd64) CC=aarch64-linux-gnu-gcc \
             SLUG=linux-aarch64 ;; \
      arm64) CC=x86_64-linux-gnu-gcc \
             SLUG=linux-amd64 ;; \
      *)     CC=gcc ;; \
    esac && \
    make -f Makefile.jni CC=$CC JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR=build/jni/$SLUG TARGET_DIR=target/classes/native/$SLUG

# Build the Java OBI agent
FROM gradle:9.6.1-jdk21-noble@sha256:79b27b5ea2d30a9e2d044098b7bd83bc15d22611166cb88eecf11a6501484c82 AS javaagent-builder

WORKDIR /build

# Copy build files
COPY pkg/internal/java .

# Pre-built native library from jni-builder stage
COPY --from=jni-builder /build/target/classes/native/linux-amd64/libobijni.so agent/target/classes/native/linux-amd64/libobijni.so
COPY --from=jni-builder /build/target/classes/native/linux-aarch64/libobijni.so agent/target/classes/native/linux-aarch64/libobijni.so

# Build the project (skip native lib compilation, already done above)
RUN gradle build -x buildNativeLib-amd64 -x buildNativeLib-aarch64 --no-daemon

# Build the autoinstrumenter binary
FROM ghcr.io/open-telemetry/obi-generator:${TAG} AS builder

ARG TARGETARCH
ARG RELEASE_VERSION=unset
ARG RELEASE_REVISION=unset

ENV GOARCH=$TARGETARCH

WORKDIR /src

RUN apk add make git bash

COPY go.mod go.sum ./
# Cache module cache.
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY bpf/ bpf/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY Makefile dependencies.Dockerfile ./
COPY --from=javaagent-builder /build/build/obi-java-agent.jar /src/pkg/internal/java/embedded/obi-java-agent.jar

# Build
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
	/generate.sh \
	&& make compile RELEASE_VERSION=${RELEASE_VERSION} RELEASE_REVISION=${RELEASE_REVISION}

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="The OpenTelemetry Authors"

WORKDIR /

COPY --from=builder /src/bin/obi .
COPY LICENSE NOTICE ./
COPY NOTICES ./NOTICES

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/obi" ]
