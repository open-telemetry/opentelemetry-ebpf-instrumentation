FROM node:20-slim@sha256:fbb357f69d05c97333855b0846e4ef65462409728312df3c9ff12c941741c0a5

WORKDIR /app

COPY internal/test/integration/components/nodemultiproc/package*.json ./
RUN npm install

COPY internal/test/integration/components/nodemultiproc/service.js .
COPY internal/test/integration/components/nodemultiproc/start-all.js .

EXPOSE 5000 5001 5002 5003

CMD [ "node", "start-all.js" ]

