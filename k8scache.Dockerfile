# Build the binary for the k8s-cache service
FROM golang:1.27.2@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS builder

ARG TARGETARCH
ARG RELEASE_VERSION=unset
ARG RELEASE_REVISION=unset
ENV GOARCH=$TARGETARCH

WORKDIR /opt/app-root

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY LICENSE LICENSE
COPY NOTICE NOTICE
COPY cmd/ cmd/
COPY pkg/ pkg/

# Build
RUN mkdir -p bin && CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build \
    -ldflags="-X 'go.opentelemetry.io/obi/pkg/buildinfo.Version=${RELEASE_VERSION}' -X 'go.opentelemetry.io/obi/pkg/buildinfo.Revision=${RELEASE_REVISION}'" \
    -o bin/k8s-cache cmd/k8s-cache/main.go

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="OpenTelemetry Authors <cncf-opentelemetry-maintainers@lists.cncf.io>"

WORKDIR /

COPY --from=builder /opt/app-root/bin/k8s-cache .
COPY --from=builder /opt/app-root/LICENSE .
COPY --from=builder /opt/app-root/NOTICE .

ENTRYPOINT [ "/k8s-cache" ]
