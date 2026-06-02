# This is a renovate-friendly source of Docker images.
FROM davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5 AS markdown
FROM gradle:9.5.1-jdk21-noble@sha256:31639c2e0433fdd7326311071c43843611295cce01c6363193a3f4cbe45b49ff AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:fc4de6036c87ecd2e64a79f6cedd9bb4b8b6a50f21c32d7f603945856ca4d586 AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:14fbf3734501e0d9179b68c952445c03fe46787ed8d6a5bb3143dcf59fef2093 AS python314
FROM golang:1.26.3@sha256:2d6c80227255c3112a4d08e67ba98e58efd3846daf15d9d7d4c389565d881b1a AS golang
FROM otel/weaver:v0.23.0@sha256:7984ecb55b859eb3034ae9d836c4eeda137e2bdd0873b7ba2bb6c3d24d6ff457 AS weaver
