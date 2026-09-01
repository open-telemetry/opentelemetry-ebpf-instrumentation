# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:32b5cdad7cce41dfd53d0ae06baebcf8357a147ee7694dc706911c373bc30c37 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.23.2@sha256:839558fd0d36c46da0e01ea84fd1d20a2822b5a8a60c16dc9708f0bb7c9e903b AS markdown
FROM gradle:9.7.1-jdk21-noble@sha256:153b5cbc7fa81767329b52f741ac63027710fed12624a0014ad1849d6a02f755 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:7ad1116be271e95f25fafb50f40e280d0373ee2c53c8dd8b5d1d77b591e62fae AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:e37a03b464436ee45750a0d027e4b802ffe579c96b78dcc7e6ef736ca8c658dd AS python314
FROM golang:1.27.0@sha256:4013ae0f9e7994f8535c58c811f8f863fbed38b72e0d51e6592156f758d66146 AS golang
FROM otel/weaver:v0.25.1@sha256:9ad46ca9cd4fa5974b121f886aa3e9946a8ef8ea905001a96c018d21f9db87ca AS weaver
