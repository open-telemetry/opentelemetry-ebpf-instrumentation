FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# avoids redownloading the whole Go dependencies on each local build
RUN go env -w GOCACHE=/go-cache
RUN go env -w GOMODCACHE=/gomod-cache

RUN apk add git bash

# Copy the go manifests and source
COPY .git/ .git/
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY internal/config/ internal/config/
COPY internal/tools/debug/ internal/tools/debug/
COPY pkg/ pkg/
COPY go.mod go.mod
COPY go.sum go.sum
COPY LICENSE LICENSE
COPY NOTICE NOTICE

RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache \
    cd internal/tools/debug && go build -o /go/bin/dlv github.com/go-delve/delve/cmd/dlv

# Prior to using this debug.Dockerfile, generate the BPF bindings with `mise run generate`.
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache \
    release_version="$(git describe --all | cut -d/ -f2-)" && \
    release_revision="$(git rev-parse --short HEAD)" && \
    mkdir -p bin && \
    CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -gcflags "-N -l" \
    -ldflags="-X 'go.opentelemetry.io/obi/pkg/buildinfo.Version=$release_version' -X 'go.opentelemetry.io/obi/pkg/buildinfo.Revision=$release_revision'" \
    -o bin/obi cmd/obi/main.go

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

WORKDIR /

COPY --from=builder /go/bin/dlv /
COPY --from=builder /src/bin/obi /
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/dlv", "--listen=:2345", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/obi" ]
