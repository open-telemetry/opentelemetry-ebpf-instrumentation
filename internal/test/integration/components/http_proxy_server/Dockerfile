FROM node:24@sha256:fdddfb3e688158251943d52eba361de991548f6814007acba4917ae6b512d6be

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/http_proxy_server .

# Install dependencies from committed lockfile
RUN npm ci

EXPOSE 3030

# Run the node app
CMD [ "node", "app" ]
