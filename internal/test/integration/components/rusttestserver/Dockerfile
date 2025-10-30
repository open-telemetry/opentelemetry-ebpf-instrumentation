FROM rust:latest@sha256:e11d5f1c3ce7dded4bbc4a40437d04a618e476ed52b05651fc967d8c55f2c33d AS rustbuilder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/rusttestserver .

# Build
RUN cargo build --release

# The App Image
FROM debian:bookworm-slim@sha256:78d2f66e0fec9e5a39fb2c72ea5e052b548df75602b5215ed01a17171529f706

RUN apt update
RUN apt install libssl3 -y
#RUN apt install strace -y

EXPOSE 8090

# Copy the native executable into the containers
COPY --from=rustbuilder /build/target/release/greetings ./greetings
COPY --from=rustbuilder /build/large_data.json ./large_data.json
ENTRYPOINT ["/greetings"]
#CMD [ "strace", "-f", "/greetings" ]