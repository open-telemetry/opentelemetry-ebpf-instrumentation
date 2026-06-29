FROM golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# avoids redownloading the whole Go dependencies on each local build
RUN go env -w GOCACHE=/go-cache
RUN go env -w GOMODCACHE=/gomod-cache

RUN apk add make git bash

# Copy the go manifests and source
COPY .git/ .git/
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY internal/tools/debug/ internal/tools/debug/
COPY pkg/ pkg/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile
COPY LICENSE LICENSE
COPY NOTICE NOTICE

# OBI's Makefile doesn't let to override BPF2GO env var: temporary hack until we can
ENV TOOLS_DIR=/go/bin
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache \
    cd internal/tools/debug && go build -o /go/bin/dlv github.com/go-delve/delve/cmd/dlv

# Prior to using this debug.Dockerfile, you should manually run `make docker-generate`
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache \
    make debug

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

WORKDIR /

COPY --from=builder /go/bin/dlv /
COPY --from=builder /src/bin/obi /
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/dlv", "--listen=:2345", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/obi" ]
