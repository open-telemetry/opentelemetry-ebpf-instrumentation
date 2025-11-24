FROM golang:1.25.3@sha256:6d4e5e74f47db00f7f24da5f53c1b4198ae46862a47395e30477365458347bf2 AS builder

WORKDIR /src

COPY . .

RUN make compile

FROM ubuntu:latest@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252

WORKDIR /
COPY --from=builder /src/bin/backend /backend

ENTRYPOINT ["/backend"]
