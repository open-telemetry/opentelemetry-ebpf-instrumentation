FROM node:20-slim@sha256:d68a804de261bfca9b12b9c8c4070f194043244d4342276c3b108fa150095ba5

WORKDIR /app

COPY internal/test/integration/components/nodemultiproc/package*.json ./
RUN npm install

COPY internal/test/integration/components/nodemultiproc/service.js .
COPY internal/test/integration/components/nodemultiproc/start-all.js .

EXPOSE 5000 5001 5002 5003

CMD [ "node", "start-all.js" ]

