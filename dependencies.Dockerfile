# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:119bdf19f884fb540a02b02534632c16525266957572e85996e377d5d41d3168 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.24.0@sha256:70ead7c0352d22d04bbe612cd96b54ec591538d8f4626cafe391bb2ecf3639ca AS markdown
FROM gradle:9.8.2-jdk21-noble@sha256:accd9bab093a3331697ede5aa9cecbb57d43217327e93d3cae989f1d28b49c0c AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:8f0d49ccab34876916fe67c6190fdf14c31cf64153dc08b73664162342f50feb AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:637619278855a77885a94312efa7decd8479ca6cec5f959e134cbab96582821e AS python314
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS golang
FROM otel/weaver:v0.27.0@sha256:3049b4079049d4abb1b5632f511ada2c33505a1c60f3f8535e93f87f0696f056 AS weaver
