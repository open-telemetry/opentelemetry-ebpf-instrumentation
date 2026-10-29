FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o /out/frontend ./cmd/frontend && \
    go build -o /out/backend ./cmd/backend

FROM alpine:3.24@sha256:c26612752c78b18faacd63c7d50f4592c2e7b0f25e0e20e82bd74e465c57ab0d
WORKDIR /app
COPY --from=builder /out/frontend /app/frontend
COPY --from=builder /out/backend /app/backend
