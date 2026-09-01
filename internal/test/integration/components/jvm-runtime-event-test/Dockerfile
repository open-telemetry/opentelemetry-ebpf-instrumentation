FROM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS go

FROM eclipse-temurin:17@sha256:b624cb9175b71aaeb654dd9def666035332d5abf70318537c1a46e61564dbecd

COPY --from=go /usr/local/go /usr/local/go

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOTOOLCHAIN=local

WORKDIR /src
