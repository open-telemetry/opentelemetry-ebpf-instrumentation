# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:32b5cdad7cce41dfd53d0ae06baebcf8357a147ee7694dc706911c373bc30c37 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.23.2@sha256:839558fd0d36c46da0e01ea84fd1d20a2822b5a8a60c16dc9708f0bb7c9e903b AS markdown
FROM gradle:9.6.1-jdk21-noble@sha256:8074080ea0c9d663076211abc189ba1472474d3019a0da49c4216dce3184cf85 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:5bb60fecc8a5f863979e08e83f4a41574dc21b3ced79a3bae682c6ee8831583a AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:dfe4069fefc02ee4d6097c26f31d0784df09c9b6242fb4a25ad31fbae74ec6aa AS python314
FROM golang:1.26.5@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS golang
FROM otel/weaver:v0.25.1@sha256:9ad46ca9cd4fa5974b121f886aa3e9946a8ef8ea905001a96c018d21f9db87ca AS weaver
