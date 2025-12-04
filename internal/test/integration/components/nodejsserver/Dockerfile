FROM node:20-slim@sha256:fbb357f69d05c97333855b0846e4ef65462409728312df3c9ff12c941741c0a5

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/nodejsserver .

# Install NodeJS express
RUN npm install express --save

EXPOSE 3030
EXPOSE 3033

# Run the node app
CMD [ "node", "app" ]
