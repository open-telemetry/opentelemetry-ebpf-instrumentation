FROM node:20-slim@sha256:f679d7699517426eb148a5698c717477fd3f8a48f6c1eaf771e390a9bb8268c8

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY test/integration/components/nodeclient/client* . 

# Run the node app
CMD [ "node", "client.js" ]
