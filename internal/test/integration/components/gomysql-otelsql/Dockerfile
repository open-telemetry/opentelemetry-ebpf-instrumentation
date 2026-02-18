# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.25.7@sha256:cc737435e2742bd6da3b7d575623968683609a3d2e0695f9d85bee84071c08e6 AS builder

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
FROM debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe

WORKDIR /
COPY --from=builder /src/gomysql_otelsql .
USER 0:0

CMD [ "/gomysql_otelsql" ]
