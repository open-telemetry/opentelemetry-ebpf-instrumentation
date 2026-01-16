# Build the autoinstrumenter binary
ARG TAG=0.2.5@sha256:35f477693b64867e40a608c6fbc3f053fd89bf87b1356374b95ef32440eb2e0b
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
FROM gradle:9.2.1-jdk21-corretto@sha256:3392a25fbe142defde5a13ec7e7171cac8c08ec6bcec00b44705d9a24b544fa3 AS javaagent-builder

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
