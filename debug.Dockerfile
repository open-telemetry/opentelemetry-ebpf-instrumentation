FROM golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS builder

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

FROM alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

WORKDIR /

COPY --from=builder /go/bin/dlv /
COPY --from=builder /src/bin/obi /
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/dlv", "--listen=:2345", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/obi" ]
