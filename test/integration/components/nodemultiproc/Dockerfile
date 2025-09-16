FROM node:20-slim@sha256:d38efce970505168e50665d2350ae7d102204235d7072a1076afbdf227c1ea17

WORKDIR /app

COPY test/integration/components/nodemultiproc/package*.json ./
RUN npm install

COPY test/integration/components/nodemultiproc/service.js .
COPY test/integration/components/nodemultiproc/start-all.js .

EXPOSE 5000 5001 5002 5003

CMD [ "node", "start-all.js" ]

