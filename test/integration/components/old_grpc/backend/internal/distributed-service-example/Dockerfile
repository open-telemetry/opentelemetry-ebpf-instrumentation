FROM golang:1.25@sha256:6ea52a02734dd15e943286b048278da1e04eca196a564578d718c7720433dbbe AS builder

WORKDIR /src

COPY . .

RUN make compile

FROM ubuntu:latest@sha256:728785b59223d755e3e5c5af178fab1be7031f3522c5ccd7a0b32b80d8248123

WORKDIR /
COPY --from=builder /src/bin/backend /backend

ENTRYPOINT ["/backend"]
