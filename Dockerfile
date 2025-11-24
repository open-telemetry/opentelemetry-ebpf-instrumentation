# Build the autoinstrumenter binary
ARG TAG=0.2.3@sha256:7d9ca3af8c0183e87d67c9507a6d8ca7ea1cea6794335e6d61514ba18ea18910
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

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="The OpenTelemetry Authors"

WORKDIR /

COPY --from=builder /src/bin/ebpf-instrument .
COPY LICENSE NOTICE .
COPY NOTICES ./NOTICES

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/ebpf-instrument" ]
