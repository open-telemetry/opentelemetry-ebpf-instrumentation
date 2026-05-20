FROM node:24-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d

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
