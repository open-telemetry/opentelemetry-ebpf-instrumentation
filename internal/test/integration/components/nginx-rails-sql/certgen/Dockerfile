FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS builder

WORKDIR /src
COPY . .
RUN GO111MODULE=off CGO_ENABLED=0 go build -o /out/certgen ./main.go

FROM scratch

COPY --from=builder /out/certgen /usr/local/bin/certgen

ENTRYPOINT ["/usr/local/bin/certgen"]
