FROM golang:1.21 AS builder

WORKDIR /src

COPY . .

RUN make compile

FROM ubuntu:latest

WORKDIR /
COPY --from=builder /src/bin/backend /backend

ENTRYPOINT ["/backend"]
