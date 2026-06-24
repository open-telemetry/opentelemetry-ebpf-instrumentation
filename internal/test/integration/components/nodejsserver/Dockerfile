FROM node:24-slim@sha256:b31e7a42fdf8b8aa5f5ed477c72d694301273f1069c5a2f71d53c6482e99a2fc

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/nodejsserver .

# Install dependencies from committed lockfile
RUN npm ci

EXPOSE 3030
EXPOSE 3033

# Run the node app
CMD [ "node", "app" ]
