FROM golang:1.26.3@sha256:efaccb5b497e90df3ebe5216cc25cd9f98e73874e2d638b56e38d4a3f098c41c AS go

FROM eclipse-temurin:25@sha256:dfc0093e3dbf43dae57827111c6e374f5b44fac19a9451584b2b336b81474d64

COPY --from=go /usr/local/go /usr/local/go

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOTOOLCHAIN=local

WORKDIR /src
