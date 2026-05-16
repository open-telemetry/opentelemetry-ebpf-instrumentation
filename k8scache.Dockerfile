# Build the binary for the k8s-cache service
FROM golang:1.26.3@sha256:2981696eed011d747340d7252620932677929cce7d2d539602f56a8d7e9b660b AS builder

ARG TARGETARCH
ENV GOARCH=$TARGETARCH

WORKDIR /opt/app-root

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY LICENSE LICENSE
COPY NOTICE NOTICE
COPY Makefile Makefile
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY .git/ .git/

# Build
RUN make compile-cache

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="OpenTelemetry Authors <cncf-opentelemetry-maintainers@lists.cncf.io>"

WORKDIR /

COPY --from=builder /opt/app-root/bin/k8s-cache .
COPY --from=builder /opt/app-root/LICENSE .
COPY --from=builder /opt/app-root/NOTICE .

ENTRYPOINT [ "/k8s-cache" ]