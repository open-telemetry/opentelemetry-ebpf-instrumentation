# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:80e38f9a1b39188b8bdb28879178edb322a4402b081a9aedda1924609decd6f6 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.24.2@sha256:c768e94d8bb161c449bde28f60656929ca1f02c3010a405f65c9cac71563a889 AS markdown
FROM gradle:9.9.2-jdk21-noble@sha256:cf8e4a8dbbe7b5efc38fb0a2a223b2acbfb9df46bb96fbe9df94be1fb0436edb AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:8f0d49ccab34876916fe67c6190fdf14c31cf64153dc08b73664162342f50feb AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:b093dbbd7963c765325ecdf866d42915f5327e135569f9dae9c77cac63559bf2 AS python314
FROM golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS golang
FROM otel/weaver:v0.28.0@sha256:5857bb81d8cc7ed608cdcae37c4b459eb020f21dd4acade35f7933cd6762fbcc AS weaver
