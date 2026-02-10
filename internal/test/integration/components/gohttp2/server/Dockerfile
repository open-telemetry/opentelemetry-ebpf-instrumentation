# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25.7@sha256:cc737435e2742bd6da3b7d575623968683609a3d2e0695f9d85bee84071c08e6 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/ internal/test/
COPY go.mod go.mod
COPY go.sum go.sum

# Build
RUN go build -o http2srv ./internal/test/integration/components/gohttp2/server/main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe

WORKDIR /
COPY --from=builder /src/http2srv .
COPY --from=builder /src/internal/test/integration/components/gohttp2/server/key.pem .
COPY --from=builder /src/internal/test/integration/components/gohttp2/server/cert.pem .
USER 0:0

CMD [ "/http2srv" ]
