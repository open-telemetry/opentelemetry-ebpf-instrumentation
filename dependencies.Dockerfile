# This is a renovate-friendly source of Docker images.
FROM davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5 AS markdown
FROM gradle:9.5.1-jdk21-noble@sha256:4702c9be8d6c3cfb45f3ea2a08ad8a51563b2851694ba00ef44259f1f70ea040 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:61d17db1210cc5fe87f0d58d76718608d0e7ea74ee13ad0f1a4bf714537c9c7d AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:3394073cf29bbeea37424b32915cd491d404c952d0ff1ef69feef080524a4c94 AS python314
FROM golang:1.26.4@sha256:68cb6d68bed024785b69195b89af7ac7a444f27791435f98647edff595aa0479 AS golang
FROM otel/weaver:v0.23.0@sha256:7984ecb55b859eb3034ae9d836c4eeda137e2bdd0873b7ba2bb6c3d24d6ff457 AS weaver
