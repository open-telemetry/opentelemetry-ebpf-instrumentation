# Build the mock OpenAI server binary
# Docker command must be invoked from the project root directory
FROM golang:1.26.0@sha256:9edf71320ef8a791c4c33ec79f90496d641f306a91fb112d3d060d5c1cee4e20 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY main.go main.go

# Build
RUN go build -o openai-mock main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /src/openai-mock .
USER 0:0

ENV OPENAI_PORT=8081
EXPOSE 8081

CMD [ "/openai-mock" ]
