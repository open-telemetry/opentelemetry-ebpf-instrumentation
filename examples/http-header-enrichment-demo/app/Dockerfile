FROM golang:1.26-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o /out/frontend ./cmd/frontend && \
    go build -o /out/backend ./cmd/backend

FROM alpine:3.23@sha256:4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b
WORKDIR /app
COPY --from=builder /out/frontend /app/frontend
COPY --from=builder /out/backend /app/backend
