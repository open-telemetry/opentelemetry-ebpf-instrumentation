FROM node:24-slim@sha256:e8e2e91b1378f83c5b2dd15f0247f34110e2fe895f6ca7719dbb780f929368eb

WORKDIR /app

COPY internal/test/integration/components/tpclient/package*.json ./
RUN npm install

COPY internal/test/integration/components/tpclient/service.js ./
COPY internal/test/integration/components/tpclient/start-all.js ./

EXPOSE 6000 6001 6002

CMD ["node", "start-all.js"]
