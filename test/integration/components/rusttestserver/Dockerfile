FROM rust:latest@sha256:976303ceda00c5f21d6fe97500927285c7e0f6a2e8df71ae18a6c8e9b37550a1 AS rustbuilder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY test/integration/components/rusttestserver .

# Build
RUN cargo build --release

# The App Image
FROM debian:bookworm-slim@sha256:7e490910eea2861b9664577a96b54ce68ea3e02ce7f51d89cb0103a6f9c386e0

RUN apt update
RUN apt install libssl3 -y
#RUN apt install strace -y

EXPOSE 8090

# Copy the native executable into the containers
COPY --from=rustbuilder /build/target/release/greetings ./greetings
COPY --from=rustbuilder /build/large_data.json ./large_data.json
ENTRYPOINT ["/greetings"]
#CMD [ "strace", "-f", "/greetings" ]