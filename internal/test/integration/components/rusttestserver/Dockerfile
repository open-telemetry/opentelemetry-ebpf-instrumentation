FROM rust:1.85.0-bookworm@sha256:0ff31c9ffa641a62e48d543fb00b4960955ea375f40776f40f585b89e654cc5e AS rustbuilder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/rusttestserver .

# Build
RUN cargo build --locked --release

# The App Image
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

RUN apt update
RUN apt install libssl3 -y
#RUN apt install strace -y

EXPOSE 8090

# Copy the native executable into the containers
COPY --from=rustbuilder /build/target/release/greetings ./greetings
COPY --from=rustbuilder /build/large_data.json ./large_data.json
ENTRYPOINT ["/greetings"]
#CMD [ "strace", "-f", "/greetings" ]