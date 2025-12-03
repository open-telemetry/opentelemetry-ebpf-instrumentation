# Dockerfile that will build a container that runs rust ironssl HTTP on port 8080
FROM rust:latest@sha256:4a29b0db5c961cd530f39276ece3eb6e66925b59599324c8c19723b72a423615
EXPOSE 8080
RUN mkdir -p /src
COPY src/main.rs /src/main.rs
COPY Cargo.toml /Cargo.toml
COPY Cargo.lock /Cargo.lock
RUN cargo build
CMD ["/target/debug/rust_pingiron"]