# Dockerfile that will build a container that runs rust basic net tcp on port 8080
FROM rust:latest@sha256:e11d5f1c3ce7dded4bbc4a40437d04a618e476ed52b05651fc967d8c55f2c33d
EXPOSE 8080
RUN mkdir -p /src
COPY src/main.rs /src/main.rs
COPY Cargo.toml /Cargo.toml
COPY Cargo.lock /Cargo.lock
RUN cargo build
CMD ["/target/debug/rust_pingserver"]