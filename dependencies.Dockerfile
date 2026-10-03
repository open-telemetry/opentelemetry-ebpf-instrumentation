# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:ea2b9914a16a4ac1981994af97b318f7c7d4db76b580c56177f08bf76f4a0be8 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.23.3@sha256:d5f3f3f04b2e285dcbcdcd13b4454d119e273e3c393a9dabd163dba4abad526d AS markdown
FROM gradle:9.7.1-jdk21-noble@sha256:153b5cbc7fa81767329b52f741ac63027710fed12624a0014ad1849d6a02f755 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:c86576f54b4fbaa45c132a694fb44f639b4f02b7fa357749e1d0f9f8190d8516 AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:8390ef751cf17813d7a30e73bb9316d43adeab121ed3ee655bb1d344393a8046 AS python314
FROM golang:1.27.1@sha256:512690a5660563b57d37ecc31129e7f136e831db2aed24a1dbeb8ad7380dc0fa AS golang
FROM otel/weaver:v0.26.1@sha256:9094862c0ab261bdbcb079bb981f9a573b3659b130a6d2ab8616eca6ba37aaec AS weaver
