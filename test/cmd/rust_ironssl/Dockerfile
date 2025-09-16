# Dockerfile that will build a container that runs rust ironssl HTTPS on port 8080
FROM rust:latest@sha256:9e1b362e100b2c510355314491708bdc59d79b8ed93e94580aba9e4a370badab
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