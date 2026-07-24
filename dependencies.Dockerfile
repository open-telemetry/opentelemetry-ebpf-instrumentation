# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:8635836765b0c4c43970660219739baa58b0883c2e429e4b8918f7dd1519455c AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.23.1@sha256:f382ea4fdc949883e79de678009437fb40c339323654c7b0dd4d5221cda8ed20 AS markdown
FROM gradle:9.6.1-jdk21-noble@sha256:d3e4ec60a75f6ada80f52e3c648ccfcbeaff4bc0d8e0f5ce55f81994763daf3c AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:4dea36dd60423e44f3bdfbf6df5cfae3ce69a692f3f58ec037fc064aab0da841 AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:72eb2e892abf4411f47544b41e94b2435e09644d768b9f183a366a6b46840569 AS python314
FROM golang:1.26.5@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS golang
FROM otel/weaver:v0.24.2@sha256:d1fb16d279f39810c340fbbf1cf9e5e995a3a9cefa531938e9012437e3bc00c1 AS weaver
