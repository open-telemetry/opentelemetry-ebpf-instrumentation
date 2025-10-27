## Adopted from https://github.com/wbotelhos/how-to-create-a-http-server-with-elixir

FROM elixir:1.19.1-slim@sha256:e8f2d0054e6403125247359e59954939fd586830ba107e239c90b84e33df124d

WORKDIR /app

# Copy the source code into the image for building
COPY test/integration/components/elixir .

# Install dependencies
RUN mix do deps.get, compile

EXPOSE 4000

# Run the node app
CMD [ "mix", "run", "--no-halt" ]
