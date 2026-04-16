ARG TAG=0.2.11@sha256:c9a11deeda1de354aa334817f693efbf5ccee15dcd18caee6a9b221eed0e5773

# Build the Java OBI agent
FROM gradle:9.3.1-jdk21-noble@sha256:f3784cc59d7fbab1e0ddb09c4cd082f13e16d3fb8c50b7922b7aeae8e9507da5 AS javaagent-builder

WORKDIR /build

# Use Azure mirror for faster downloads on GitHub Actions runners (actions/runner-images#7048)
RUN sed -i 's|archive.ubuntu.com|azure.archive.ubuntu.com|g' /etc/apt/sources.list.d/*.sources && \
    apt update && apt install -y clang llvm

# Copy build files
COPY pkg/internal/java .

# Build the project
RUN gradle build --no-daemon

# Build the autoinstrumenter binary
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
COPY Makefile dependencies.Dockerfile ./
COPY --from=javaagent-builder /build/build/obi-java-agent.jar /src/pkg/internal/java/embedded/obi-java-agent.jar

# Build
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
	/generate.sh \
	&& make compile

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="The OpenTelemetry Authors"

WORKDIR /

COPY --from=builder /src/bin/obi .
COPY LICENSE NOTICE ./
COPY NOTICES ./NOTICES

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/obi" ]
