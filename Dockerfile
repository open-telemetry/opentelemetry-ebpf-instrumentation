# Build the autoinstrumenter binary
ARG TAG=0.2.6@sha256:547007f27e8323ace60428fe02cb29a512e312fd23e706dd4e061e63c80e4167
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
FROM gradle:9.3.0-jdk21-corretto@sha256:2458e66c572212fd24f55ffecde7b88fafdba81e6017eb741179d80cb03d153a AS javaagent-builder

WORKDIR /build

# Copy build files
COPY pkg/internal/java .

# Build the project
RUN ./gradlew build --no-daemon

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="The OpenTelemetry Authors"

WORKDIR /

COPY --from=builder /src/bin/ebpf-instrument .
COPY --from=javaagent-builder /build/build/obi-java-agent.jar .
COPY LICENSE NOTICE .
COPY NOTICES ./NOTICES

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/ebpf-instrument" ]
