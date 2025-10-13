## Adopted from https://github.com/wbotelhos/how-to-create-a-http-server-with-elixir

FROM elixir:1.18.4-slim@sha256:8d82441aebf44ac1ba43b5a0f220df2b893189fc54004ac5bdc954704c8c4e98

WORKDIR /app

# Copy the source code into the image for building
COPY test/integration/components/elixir .

# Install dependencies
RUN mix do deps.get, compile

EXPOSE 4000

# Run the node app
CMD [ "mix", "run", "--no-halt" ]
