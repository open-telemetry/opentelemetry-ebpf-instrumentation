FROM node:24-slim@sha256:c2d5ade763cacfb03fe9cb8e8af5d1be5041ff331921fa26a9b231ca3a4f780a

WORKDIR /app

COPY internal/test/integration/components/tpclient/package*.json ./
RUN npm ci

COPY internal/test/integration/components/tpclient/service.js ./
COPY internal/test/integration/components/tpclient/start-all.js ./

EXPOSE 6000 6001 6002

CMD ["node", "start-all.js"]
