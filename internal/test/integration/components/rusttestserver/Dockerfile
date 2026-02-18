FROM rust:latest@sha256:80302520b7199f0504975bca59a914015e9fee088f759875dbbc238ca9509ee1 AS rustbuilder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/rusttestserver .

# Build
RUN cargo build --release

# The App Image
FROM debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe

RUN apt update
RUN apt install libssl3 -y
#RUN apt install strace -y

EXPOSE 8090

# Copy the native executable into the containers
COPY --from=rustbuilder /build/target/release/greetings ./greetings
COPY --from=rustbuilder /build/large_data.json ./large_data.json
ENTRYPOINT ["/greetings"]
#CMD [ "strace", "-f", "/greetings" ]