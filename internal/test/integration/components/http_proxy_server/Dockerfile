FROM node:20@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/http_proxy_server .

# Install dependencies from committed lockfile
RUN npm ci

EXPOSE 3030

# Run the node app
CMD [ "node", "app" ]
