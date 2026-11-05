# Builds the central metadata service for the peer metadata integration tests.
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

ARG TARGETARCH
ENV GOARCH=$TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY pkg/ pkg/

RUN CGO_ENABLED=0 go build -o /metadata-service ./cmd/metadata-service

FROM scratch

COPY --from=builder /metadata-service /metadata-service

ENTRYPOINT [ "/metadata-service" ]
