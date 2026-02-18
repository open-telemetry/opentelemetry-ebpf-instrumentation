# Build the autoinstrumenter binary
ARG TAG=0.2.9@sha256:5dc5c5d80515637e31dd3095e60b76fec8fd8793962240eb0bc8d9b201011417
FROM ghcr.io/open-telemetry/obi-generator:${TAG} AS builder

# TODO: embed software version in executable

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

RUN apk add make git bash

COPY go.mod go.sum ./
# Cache module cache.
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY .git/ .git/
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY Makefile dependencies.Dockerfile .

# Build
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
	/generate.sh \
	&& make compile

# Build the Java OBI agent
FROM gradle:9.3.1-jdk21-noble@sha256:5f836f4642496f816f15d495b007e1912f36bf58fbea0247c0b761af438d7cf2 AS javaagent-builder

WORKDIR /build

RUN apt update
RUN apt install -y clang llvm

# Copy build files
COPY pkg/internal/java .

# Build the project
RUN ./gradlew build --no-daemon

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="The OpenTelemetry Authors"

WORKDIR /

COPY --from=builder /src/bin/obi .
COPY --from=javaagent-builder /build/build/obi-java-agent.jar .
COPY LICENSE NOTICE .
COPY NOTICES ./NOTICES

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/obi" ]
