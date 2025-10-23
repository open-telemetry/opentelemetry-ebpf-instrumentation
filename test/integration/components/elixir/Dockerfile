## Adopted from https://github.com/wbotelhos/how-to-create-a-http-server-with-elixir

FROM elixir:1.18.4-slim@sha256:7998946434dd3ddafc88effcf48d37bb5e2301cec3ec540048df9226c6da55ae

WORKDIR /app

# Copy the source code into the image for building
COPY test/integration/components/elixir .

# Install dependencies
RUN mix do deps.get, compile

EXPOSE 4000

# Run the node app
CMD [ "mix", "run", "--no-halt" ]
