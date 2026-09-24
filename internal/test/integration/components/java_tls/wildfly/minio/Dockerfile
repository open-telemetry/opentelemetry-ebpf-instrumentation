FROM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS certs

WORKDIR /certs

RUN go run github.com/minio/certgen@v1.4.0 -host minio

FROM alpine/minio:RELEASE.2025-10-15T17-29-55Z@sha256:cf23643a6cf9ce159c57643ceb88279e431262282428c9e0bf3a7ef1a97e84b4

COPY --from=certs --chown=minio:minio /certs/public.crt /certs/private.key /certs/
