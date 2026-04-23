FROM golang:1.25.8@sha256:f55a6ec7f24aedc1ed66e2641fdc52de01f2d24d6e49d1fa38582c07dd5f601d AS builder

WORKDIR /src
COPY . .
RUN GO111MODULE=off CGO_ENABLED=0 go build -o /out/certgen ./main.go

FROM scratch

COPY --from=builder /out/certgen /usr/local/bin/certgen

ENTRYPOINT ["/usr/local/bin/certgen"]
