## Adopted from https://github.com/wbotelhos/how-to-create-a-http-server-with-elixir

FROM elixir:1.19.4-slim@sha256:f1168ed72410aa1b7a495f01b4c9c9e28a977fc1ce9ee8bea1939a814f299c84

WORKDIR /app

# Copy the source code into the image for building
COPY internal/test/integration/components/elixir .

# Install dependencies
RUN mix do deps.get, compile

EXPOSE 4000

# Run the node app
CMD [ "mix", "run", "--no-halt" ]
