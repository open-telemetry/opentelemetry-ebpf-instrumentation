FROM node:20-slim@sha256:d38efce970505168e50665d2350ae7d102204235d7072a1076afbdf227c1ea17

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY test/integration/components/nodeclient/client* . 

# Run the node app
CMD [ "node", "client.js" ]
