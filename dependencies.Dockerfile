# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:32b5cdad7cce41dfd53d0ae06baebcf8357a147ee7694dc706911c373bc30c37 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.23.2@sha256:839558fd0d36c46da0e01ea84fd1d20a2822b5a8a60c16dc9708f0bb7c9e903b AS markdown
FROM gradle:9.7.1-jdk21-noble@sha256:153b5cbc7fa81767329b52f741ac63027710fed12624a0014ad1849d6a02f755 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:9e5de92d740a024926ebb4f7d5ab5642fd2756d8a0b2eabb77282bee17593523 AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:d5ddd498c5a28ec77ff1c70276f8f3c4a116a303c8b5583a018ea43c2e89e366 AS python314
FROM golang:1.27.1@sha256:512690a5660563b57d37ecc31129e7f136e831db2aed24a1dbeb8ad7380dc0fa AS golang
FROM otel/weaver:v0.26.1@sha256:9094862c0ab261bdbcb079bb981f9a573b3659b130a6d2ab8616eca6ba37aaec AS weaver
