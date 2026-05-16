# This is a renovate-friendly source of Docker images.
FROM davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5 AS markdown
FROM gradle:9.5.0-jdk21-noble@sha256:41cd88d5934d5880ea7e3ebd53d711155e7e1c989390f0f9fa3dfd7d6b742a28 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:fbb7e5d53e301bb69abc8f755a8b490c2e737a6a9bdef5e01d506de42783bc1b AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:f0b28d1878fdb33b1d610c3703eac64446da74258f323bd154dbe4945a177fa4 AS python314
FROM golang:1.26.3@sha256:2981696eed011d747340d7252620932677929cce7d2d539602f56a8d7e9b660b AS golang
FROM otel/weaver:v0.23.0@sha256:7984ecb55b859eb3034ae9d836c4eeda137e2bdd0873b7ba2bb6c3d24d6ff457 AS weaver
