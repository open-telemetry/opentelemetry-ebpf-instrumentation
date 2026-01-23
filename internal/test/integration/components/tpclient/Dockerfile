FROM node:20-slim

WORKDIR /app

COPY internal/test/integration/components/tpclient/package*.json ./
RUN npm install

COPY internal/test/integration/components/tpclient/service.js ./
COPY internal/test/integration/components/tpclient/start-all.js ./

EXPOSE 6000 6001 6002

CMD ["node", "start-all.js"]
