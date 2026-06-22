FROM node:24@sha256:032e78d7e54e352129831743737e3a83171d9cc5b5896f411649c597ce0b11ea

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/http_proxy_server .

# Install dependencies from committed lockfile
RUN npm ci

EXPOSE 3030

# Run the node app
CMD [ "node", "app" ]
