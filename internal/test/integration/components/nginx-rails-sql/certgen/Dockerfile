FROM golang:1.25.9@sha256:8a7adc288b77e9b787cd2695029eb54d10ae80571b21d44fed68d067ad0a9c96 AS builder

WORKDIR /src
COPY . .
RUN GO111MODULE=off CGO_ENABLED=0 go build -o /out/certgen ./main.go

FROM scratch

COPY --from=builder /out/certgen /usr/local/bin/certgen

ENTRYPOINT ["/usr/local/bin/certgen"]
