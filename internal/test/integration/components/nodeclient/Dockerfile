FROM node:20-slim@sha256:d68a804de261bfca9b12b9c8c4070f194043244d4342276c3b108fa150095ba5

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/nodeclient/client* .

# Run the node app
CMD [ "node", "client.js" ]
