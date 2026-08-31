# Build the testclient binary
# Docker command must be invoked from the project root directory
FROM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/integration/components/go-stat-metrics-client/ .

# Build
RUN go mod download && go build -o testclient main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe

WORKDIR /
COPY --from=builder /src/testclient .
USER 0:0

CMD [ "/testclient" ]

