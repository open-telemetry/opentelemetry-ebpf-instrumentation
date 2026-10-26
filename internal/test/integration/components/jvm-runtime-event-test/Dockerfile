FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS go

FROM eclipse-temurin:17@sha256:b624cb9175b71aaeb654dd9def666035332d5abf70318537c1a46e61564dbecd

COPY --from=go /usr/local/go /usr/local/go

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOTOOLCHAIN=local

WORKDIR /src
