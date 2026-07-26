FROM node:20-slim@sha256:d8a35d586fad3af7abb6fdb9ba972388395405f4d462da9e4a4ddcde67b5e0fb

WORKDIR /

COPY internal/test/integration/components/nodebullmq .

RUN npm ci

EXPOSE 3040

CMD [ "node", "worker" ]
