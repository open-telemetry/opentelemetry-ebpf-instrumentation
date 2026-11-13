FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod GO111MODULE=off CGO_ENABLED=0 go build -o /out/certgen ./main.go

FROM scratch

COPY --from=builder /out/certgen /usr/local/bin/certgen

ENTRYPOINT ["/usr/local/bin/certgen"]
