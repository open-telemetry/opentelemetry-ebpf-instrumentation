FROM golang:1.21@sha256:4746d26432a9117a5f58e95cb9f954ddf0de128e9d5816886514199316e4a2fb AS builder

WORKDIR /src

COPY . .

RUN make compile

FROM ubuntu:latest@sha256:728785b59223d755e3e5c5af178fab1be7031f3522c5ccd7a0b32b80d8248123

WORKDIR /
COPY --from=builder /src/bin/backend /backend

ENTRYPOINT ["/backend"]
