# This is a renovate-friendly source of Docker images.
FROM davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5 AS markdown
FROM gradle:9.5.1-jdk21-noble@sha256:7ec9cea59f10fc8cdf4cbcf108dfdd2d7e7d81e866e39caf244333367a49b049 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:19e8c075745abfc407b713724bce131e0f6fb1b2d5dcea9bc496c37a547ff12e AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:2e56abd547ae66fa0e46597dd68b2a45445319413084a973e1b2613ee154c3a6 AS python314
FROM golang:1.26.3@sha256:2d6c80227255c3112a4d08e67ba98e58efd3846daf15d9d7d4c389565d881b1a AS golang
FROM otel/weaver:v0.23.0@sha256:7984ecb55b859eb3034ae9d836c4eeda137e2bdd0873b7ba2bb6c3d24d6ff457 AS weaver
