# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.25.7@sha256:931c889bca758a82fcbfcb1b6ed6ca1de30783e9e52e6093ad50060735cb99be AS builder

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
