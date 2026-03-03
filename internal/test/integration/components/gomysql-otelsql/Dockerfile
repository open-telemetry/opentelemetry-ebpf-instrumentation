# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.26.0@sha256:fb612b7831d53a89cbc0aaa7855b69ad7b0caf603715860cf538df854d047b84 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY go.mod go.mod
COPY gomysql_otelsql.go gomysql_otelsql.go

# Build - download dependencies and build
RUN go mod tidy
RUN go build -o gomysql_otelsql gomysql_otelsql.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /src/gomysql_otelsql .
USER 0:0

CMD [ "/gomysql_otelsql" ]
