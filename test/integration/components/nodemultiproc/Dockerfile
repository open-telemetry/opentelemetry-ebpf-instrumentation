FROM node:20-slim@sha256:f679d7699517426eb148a5698c717477fd3f8a48f6c1eaf771e390a9bb8268c8

WORKDIR /app

COPY test/integration/components/nodemultiproc/package*.json ./
RUN npm install

COPY test/integration/components/nodemultiproc/service.js .
COPY test/integration/components/nodemultiproc/start-all.js .

EXPOSE 5000 5001 5002 5003

CMD [ "node", "start-all.js" ]

