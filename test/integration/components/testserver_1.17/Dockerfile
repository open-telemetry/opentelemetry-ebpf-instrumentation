# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25.3@sha256:6ea52a02734dd15e943286b048278da1e04eca196a564578d718c7720433dbbe AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY test/integration/components/testserver_1.17/ .

# Build
RUN go build -o testserver testserver.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:7e490910eea2861b9664577a96b54ce68ea3e02ce7f51d89cb0103a6f9c386e0

WORKDIR /
COPY --from=builder /src/testserver .
USER 0:0

CMD [ "/testserver" ]