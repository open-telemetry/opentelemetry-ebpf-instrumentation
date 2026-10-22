FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS certs

WORKDIR /certs

RUN go run github.com/minio/certgen@v1.4.0 -host minio

FROM alpine/minio:RELEASE.2025-10-15T17-29-55Z@sha256:cf23643a6cf9ce159c57643ceb88279e431262282428c9e0bf3a7ef1a97e84b4

COPY --from=certs --chown=minio:minio /certs/public.crt /certs/private.key /certs/
