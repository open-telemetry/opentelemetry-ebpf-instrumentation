# Build the mock Qwen server binary
# Docker command must be invoked from the project root directory
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY main.go main.go

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod go build -o qwen-mock main.go

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /src/qwen-mock .
USER 0:0

ENV QWEN_PORT=8085
EXPOSE 8085

CMD [ "/qwen-mock" ]
