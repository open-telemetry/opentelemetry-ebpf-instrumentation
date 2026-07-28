FROM denoland/deno:2.9.4@sha256:c777b4b225501a61074837e90a826a58f99124837824023cd60334b1e2374498

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/nodejsserver .

# Install npm deps into node_modules from package.json/lockfile
RUN deno install --allow-scripts

EXPOSE 3030
EXPOSE 3033

# Deno needs explicit permissions
CMD [ "deno", "run", "--allow-net", "--allow-env", "app.js" ]