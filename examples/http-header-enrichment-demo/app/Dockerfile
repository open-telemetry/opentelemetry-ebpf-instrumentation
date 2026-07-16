FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder
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
