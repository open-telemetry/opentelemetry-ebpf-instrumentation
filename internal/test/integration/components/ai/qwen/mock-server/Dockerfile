# Build the mock Qwen server binary
# Docker command must be invoked from the project root directory
FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY main.go main.go

RUN go build -o qwen-mock main.go

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /src/qwen-mock .
USER 0:0

ENV QWEN_PORT=8085
EXPOSE 8085

CMD [ "/qwen-mock" ]
