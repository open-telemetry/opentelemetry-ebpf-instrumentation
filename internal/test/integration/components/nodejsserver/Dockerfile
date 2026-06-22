FROM node:24-slim@sha256:c2d5ade763cacfb03fe9cb8e8af5d1be5041ff331921fa26a9b231ca3a4f780a

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
