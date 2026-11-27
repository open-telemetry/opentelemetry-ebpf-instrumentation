FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

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
COPY internal/config/ internal/config/
COPY internal/rustexec/ internal/rustexec/
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

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

WORKDIR /

COPY --from=builder /go/bin/dlv /
COPY --from=builder /src/bin/obi /
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/dlv", "--listen=:2345", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/obi" ]
