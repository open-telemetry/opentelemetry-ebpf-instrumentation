# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:ea2b9914a16a4ac1981994af97b318f7c7d4db76b580c56177f08bf76f4a0be8 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.23.3@sha256:d5f3f3f04b2e285dcbcdcd13b4454d119e273e3c393a9dabd163dba4abad526d AS markdown
FROM gradle:9.8.1-jdk21-noble@sha256:d879477a2197b2b8a5eb910d007f0b1594eb440aa2740baac17ea245fcfb02f7 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:163d47da82bcbf6eb8a92619e3463d86cde1740a7d5cf38511b2a7f1c5e263f5 AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:8e70ac2e85d09a5bb7ef09753b80671a60a71c8d24f195e4890d71e03865e36d AS python314
FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS golang
FROM otel/weaver:v0.27.0@sha256:3049b4079049d4abb1b5632f511ada2c33505a1c60f3f8535e93f87f0696f056 AS weaver
