FROM node:20-slim@sha256:d68a804de261bfca9b12b9c8c4070f194043244d4342276c3b108fa150095ba5

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
