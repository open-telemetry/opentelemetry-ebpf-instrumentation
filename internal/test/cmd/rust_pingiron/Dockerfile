# Dockerfile that will build a container that runs rust ironssl HTTP on port 8080
FROM rust:latest@sha256:65734d21f103d104fe0d9e508a424f7f60abd10e489d36de8bd36ae6c80e746d
EXPOSE 8080
RUN mkdir -p /src
COPY src/main.rs /src/main.rs
COPY Cargo.toml /Cargo.toml
COPY Cargo.lock /Cargo.lock
RUN cargo build
CMD ["/target/debug/rust_pingiron"]