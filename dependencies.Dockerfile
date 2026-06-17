# This is a renovate-friendly source of Docker images.
FROM davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5 AS markdown
FROM gradle:9.5.1-jdk21-noble@sha256:4702c9be8d6c3cfb45f3ea2a08ad8a51563b2851694ba00ef44259f1f70ea040 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:6d8550ce7be4011c18a5a6b66016cf8cedfd535c86f93126e1e7bb917510d1b3 AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:bebc7d6de6dd015a483903461eaedea12805728be6f9a044ca7106a2f7e11ddf AS python314
FROM golang:1.26.4@sha256:792443b89f65105abba56b9bd5e97f680a80074ac62fc844a584212f8c8102c3 AS golang
FROM otel/weaver:v0.23.0@sha256:7984ecb55b859eb3034ae9d836c4eeda137e2bdd0873b7ba2bb6c3d24d6ff457 AS weaver
