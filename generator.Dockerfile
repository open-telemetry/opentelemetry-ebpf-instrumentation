FROM golang:1.24.6-alpine@sha256:c8c5f95d64aa79b6547f3b626eb84b16a7ce18a139e3e9ca19a8c078b85ba80d AS base
FROM base AS builder

WORKDIR /build

COPY cmd/obi-genfiles/obi_genfiles.go .
COPY go.mod go.mod
COPY go.sum go.sum
RUN go build -o obi_genfiles obi_genfiles.go

FROM base AS dist

WORKDIR /src

ENV EBPF_VER=v0.19.0

RUN apk add clang llvm20 wget
RUN apk cache purge
RUN go install github.com/cilium/ebpf/cmd/bpf2go@$EBPF_VER
COPY --from=builder /build/obi_genfiles /go/bin

RUN cat <<EOF > /generate.sh
#!/bin/sh
export GOCACHE=/tmp
export GOMODCACHE=/tmp/go-mod-cache
export BPF2GO=bpf2go
export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g -Wall -Werror"
export OTEL_EBPF_GENFILES_RUN_LOCALLY=1
export OTEL_EBPF_GENFILES_MODULE_ROOT="/src"
obi_genfiles
EOF

RUN chmod +x /generate.sh

ENTRYPOINT ["/generate.sh"]

