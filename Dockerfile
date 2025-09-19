# Build the autoinstrumenter binary
FROM ghcr.io/open-telemetry/obi-generator:0.2.2@sha256:e2adc24c661f612708f8627441f46fe24eb1c9dc37d4e4acf9bfab90f6ece510 AS builder

# TODO: embed software version in executable

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

RUN apk add make git bash

# Copy the go manifests and source
COPY .git/ .git/
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile
COPY LICENSE LICENSE
COPY NOTICE NOTICE

# Build
RUN /generate.sh
RUN make compile

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="The OpenTelemetry Authors"

WORKDIR /

COPY --from=builder /src/bin/ebpf-instrument .
COPY --from=builder /src/LICENSE .
COPY --from=builder /src/NOTICE .
COPY NOTICES ./NOTICES

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/ebpf-instrument" ]
