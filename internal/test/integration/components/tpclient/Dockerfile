FROM node:20-slim@sha256:d8a35d586fad3af7abb6fdb9ba972388395405f4d462da9e4a4ddcde67b5e0fb

WORKDIR /app

COPY internal/test/integration/components/tpclient/package*.json ./
RUN npm ci

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

COPY internal/test/integration/components/tpclient/service.js ./
COPY internal/test/integration/components/tpclient/start-all.js ./

RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
    -sha256 -days 3650 -nodes -subj "/CN=localhost"

EXPOSE 6000 6001 6002 7000 7001 7002

CMD ["node", "start-all.js"]
