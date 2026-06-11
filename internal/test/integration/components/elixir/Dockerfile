## Adopted from https://github.com/wbotelhos/how-to-create-a-http-server-with-elixir

FROM elixir:1.20.0-slim@sha256:ecfa93897706d964383feeaa130afa1496617a1333aaa982edcc559a45e79bf6

WORKDIR /app

# Copy the source code into the image for building
COPY internal/test/integration/components/elixir .

# Install dependencies
RUN mix do deps.get, compile

EXPOSE 4000

# Run the node app
CMD [ "mix", "run", "--no-halt" ]
