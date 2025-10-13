# Dockerfile that will build a container that runs rust basic net tcp on port 8080
FROM rust:latest@sha256:976303ceda00c5f21d6fe97500927285c7e0f6a2e8df71ae18a6c8e9b37550a1
EXPOSE 8080
RUN mkdir -p /src
COPY src/main.rs /src/main.rs
COPY Cargo.toml /Cargo.toml
COPY Cargo.lock /Cargo.lock
RUN cargo build
CMD ["/target/debug/rust_pingserver"]