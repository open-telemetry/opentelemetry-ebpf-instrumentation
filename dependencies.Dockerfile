# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:80e38f9a1b39188b8bdb28879178edb322a4402b081a9aedda1924609decd6f6 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.24.0@sha256:70ead7c0352d22d04bbe612cd96b54ec591538d8f4626cafe391bb2ecf3639ca AS markdown
FROM gradle:9.8.2-jdk21-noble@sha256:1278203f5f52e4781e6d7096250375a4d54ab599f26e5ba44e672b4bdbd793f7 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:8f0d49ccab34876916fe67c6190fdf14c31cf64153dc08b73664162342f50feb AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:e80c05a310400cfc90af00b5b7271ef9ad24816e3265e1162af8a678e1aad099 AS python314
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS golang
FROM otel/weaver:v0.28.0@sha256:5857bb81d8cc7ed608cdcae37c4b459eb020f21dd4acade35f7933cd6762fbcc AS weaver
