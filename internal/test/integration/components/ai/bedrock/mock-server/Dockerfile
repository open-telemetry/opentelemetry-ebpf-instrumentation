# Build the mock Bedrock server binary
# Docker command must be invoked from the project root directory
FROM golang:1.25.9@sha256:8a7adc288b77e9b787cd2695029eb54d10ae80571b21d44fed68d067ad0a9c96 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY main.go main.go

# Build
RUN go build -o bedrock-mock main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /src/bedrock-mock .
USER 0:0

ENV BEDROCK_PORT=8086
EXPOSE 8086

CMD [ "/bedrock-mock" ]
