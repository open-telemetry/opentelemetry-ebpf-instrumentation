# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:32b5cdad7cce41dfd53d0ae06baebcf8357a147ee7694dc706911c373bc30c37 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.23.2@sha256:839558fd0d36c46da0e01ea84fd1d20a2822b5a8a60c16dc9708f0bb7c9e903b AS markdown
FROM gradle:9.7.1-jdk21-noble@sha256:c60d2850fdb7c873ef390b7543df11f0b75c9fbad8ee7a054d7b7d34f7a73170 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:48acef9b19e8d955e9ddbed013761a965e347b4d742329cb295eda4aef017b4c AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:63018e7b676ef735eee4da4f9c2e7b5f5e3851fa023745d78ce91d1a099a35fd AS python314
FROM golang:1.27.1@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS golang
FROM otel/weaver:v0.26.1@sha256:9094862c0ab261bdbcb079bb981f9a573b3659b130a6d2ab8616eca6ba37aaec AS weaver
