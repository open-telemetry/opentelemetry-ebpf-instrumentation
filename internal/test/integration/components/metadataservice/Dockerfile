# Builds the central metadata service for the peer metadata integration tests.
FROM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS builder

ARG TARGETARCH
ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd/ cmd/
COPY pkg/ pkg/

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod CGO_ENABLED=0 go build -o /metadata-service ./cmd/metadata-service

FROM scratch

COPY --from=builder /metadata-service /metadata-service

ENTRYPOINT [ "/metadata-service" ]
