# Docker command must be invoked from the project root directory
ARG GO_EXCEPTIONS_GO_IMAGE=golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b
FROM ${GO_EXCEPTIONS_GO_IMAGE} AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH CGO_ENABLED=0

# Outside the OBI module: the fixture only needs the standard library.
WORKDIR /build
COPY internal/test/integration/components/go-exceptions/main.go .

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod go build -o out/go-exceptions main.go && \
    go build -ldflags="-s -w" -o out/go-exceptions-stripped main.go && \
    go build -buildmode=pie -o out/go-exceptions-pie main.go && \
    go build -buildmode=pie -ldflags="-s -w" -o out/go-exceptions-stripped-pie main.go && \
    go build -trimpath -o out/go-exceptions-trimpath main.go && \
    CGO_ENABLED=1 go build -o out/go-exceptions-cgo main.go && \
    CGO_ENABLED=1 go build -ldflags="-linkmode external -extldflags -static" -o out/go-exceptions-static-cgo main.go

# The newest glibc of the builders, for the dynamically linked cgo build
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

COPY --from=builder /build/out/ /

CMD [ "/go-exceptions" ]
