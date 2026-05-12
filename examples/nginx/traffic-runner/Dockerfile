FROM bash:5.3.8-alpine3.22@sha256:84e9597a44c52678823f5292b595004b0bccc722092b0764cb4269e2859f540a

RUN apk add --no-cache curl

WORKDIR /app

COPY generate-traffic.sh /app/generate-traffic.sh

ENTRYPOINT ["bash", "/app/generate-traffic.sh"]
