# This is a renovate-friendly source of Docker images.
FROM davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5 AS markdown
FROM gradle:9.5.0-jdk21-noble@sha256:a7647686fbef2a7f2f84b25192433c83642a9e0b2d1bbe48bc5f489a589560db AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:9d292e004ee37686d86c09ec879000bfda0b4ba336a78842fd4555ad84efa0fb AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:3e70f580d0e63d78408c35d332d780024b6e1d46d9744c888e22fa944393448e AS python314
FROM golang:1.26.3@sha256:efaccb5b497e90df3ebe5216cc25cd9f98e73874e2d638b56e38d4a3f098c41c AS golang
FROM otel/weaver:v0.23.0@sha256:7984ecb55b859eb3034ae9d836c4eeda137e2bdd0873b7ba2bb6c3d24d6ff457 AS weaver
