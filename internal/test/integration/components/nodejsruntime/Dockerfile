FROM node:20-slim@sha256:d8a35d586fad3af7abb6fdb9ba972388395405f4d462da9e4a4ddcde67b5e0fb

WORKDIR /app

# Self-contained app, no npm dependencies
COPY internal/test/integration/components/nodejsruntime/app.js .

EXPOSE 3030

# --expose-gc: the app's /gc endpoint forces a major collection via global.gc
CMD [ "node", "--expose-gc", "app.js" ]
