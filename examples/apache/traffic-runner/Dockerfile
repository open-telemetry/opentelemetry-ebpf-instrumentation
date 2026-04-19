FROM bash:5.2.37-alpine3.22@sha256:a4b03e1bbd85d85af7f5db16d2c4337aa852b8b40f3df8346624a4b9e06c1f7c

RUN apk add --no-cache curl

WORKDIR /app

COPY generate-traffic.sh /app/generate-traffic.sh

ENTRYPOINT ["bash", "/app/generate-traffic.sh"]
