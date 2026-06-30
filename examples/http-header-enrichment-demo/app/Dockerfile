FROM golang:1.26-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o /out/frontend ./cmd/frontend && \
    go build -o /out/backend ./cmd/backend

FROM alpine:3.24@sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f
WORKDIR /app
COPY --from=builder /out/frontend /app/frontend
COPY --from=builder /out/backend /app/backend
