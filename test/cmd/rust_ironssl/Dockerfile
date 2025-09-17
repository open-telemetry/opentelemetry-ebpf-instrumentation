# Dockerfile that will build a container that runs rust ironssl HTTPS on port 8080
FROM rust:latest@sha256:57407b378b2b6e07b48a6135a20c87cc22ea6e249c0acf6cb1833ead3cf116e9
EXPOSE 8080
RUN mkdir -p /src
COPY src/main.rs /src/main.rs
COPY Cargo.toml /Cargo.toml
COPY Cargo.lock /Cargo.lock
COPY localhost.crt /localhost.crt
COPY localhost.key /localhost.key
COPY identity.p12 /identity.p12
RUN cargo build
CMD ["/target/debug/rust_ironssl"]