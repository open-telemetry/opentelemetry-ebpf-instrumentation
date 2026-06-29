# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:19b646668802469d968a05342a601e78da4322a414a7c09b1c9ee25165042138 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5 AS markdown
FROM gradle:9.6.0-jdk21-noble@sha256:9cb63c2ebb4121e92aa7ed9b781a0ee154bd7ea3e45f97dbeabf7b1d3f910667 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:b0c547dc901317540957794bf099c1cc2229edd1a8610d672388d035eb815c5b AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:ac6a11294d8d964632c4000cba0f81a508befd7d4cdaf6022cde9e4655bc641e AS python314
FROM golang:1.26.4@sha256:792443b89f65105abba56b9bd5e97f680a80074ac62fc844a584212f8c8102c3 AS golang
FROM otel/weaver:v0.24.1@sha256:263964a7d444e77812f7a2d654e17683c4760a968c91278acdb7a44c20ccd572 AS weaver
