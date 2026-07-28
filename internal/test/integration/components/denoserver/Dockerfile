FROM denoland/deno:2.9.4@sha256:c777b4b225501a61074837e90a826a58f99124837824023cd60334b1e2374498

# Set the working directory to /build
WORKDIR /

# Copy the native Deno test server source
COPY internal/test/integration/components/denoserver .

EXPOSE 3030
EXPOSE 3033

# Native Deno needs explicit permissions: net for Deno.serve and fetch, read for
# the TLS cert/key used by app_tls.js, env for runtime configuration.
CMD [ "deno", "run", "--allow-net", "--allow-env", "--allow-read", "app.js" ]
