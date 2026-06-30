# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:8635836765b0c4c43970660219739baa58b0883c2e429e4b8918f7dd1519455c AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5 AS markdown
FROM gradle:9.6.1-jdk21-noble@sha256:79b27b5ea2d30a9e2d044098b7bd83bc15d22611166cb88eecf11a6501484c82 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:e798214b3d48bf7be9d207bb4f8cea18b54812cf5122e39178a194c6535cbfff AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:d21c2dd538d409d050027f67cd09f0b84882cf59072cf77720b15e21f3fe6af5 AS python314
FROM golang:1.26.4@sha256:f96cc555eb8db430159a3aa6797cd5bae561945b7b0fe7d0e284c63a3b291609 AS golang
FROM otel/weaver:v0.24.2@sha256:d1fb16d279f39810c340fbbf1cf9e5e995a3a9cefa531938e9012437e3bc00c1 AS weaver
