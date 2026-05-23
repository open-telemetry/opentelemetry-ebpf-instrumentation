# This is a renovate-friendly source of Docker images.
FROM davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5 AS markdown
FROM gradle:9.5.1-jdk21-noble@sha256:31639c2e0433fdd7326311071c43843611295cce01c6363193a3f4cbe45b49ff AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:aee4a4cc9b167028350f1bd7cf983991723b12ae1241a30d08c717282baac86c AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:1b882e1fa1834b0c26764ad6494e3151de499ed34dfa13826f9f395f5110f519 AS python314
FROM golang:1.26.3@sha256:313faae491b410a35402c05d35e7518ae99103d957308e940e1ae2cfa0aac29b AS golang
FROM otel/weaver:v0.23.0@sha256:7984ecb55b859eb3034ae9d836c4eeda137e2bdd0873b7ba2bb6c3d24d6ff457 AS weaver
