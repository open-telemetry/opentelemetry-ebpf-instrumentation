# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:8635836765b0c4c43970660219739baa58b0883c2e429e4b8918f7dd1519455c AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.23.2@sha256:839558fd0d36c46da0e01ea84fd1d20a2822b5a8a60c16dc9708f0bb7c9e903b AS markdown
FROM gradle:9.6.1-jdk21-noble@sha256:d3e4ec60a75f6ada80f52e3c648ccfcbeaff4bc0d8e0f5ce55f81994763daf3c AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:a383cbce4fff5af7afb904d85bebf0868d0c41d7231dc43a4f0962fb041bbf0f AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:2e5867a06156cb8be272125d32fc5032ed750a1268a9350d87a7d322540eb59f AS python314
FROM golang:1.26.5@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS golang
FROM otel/weaver:v0.25.0@sha256:bef6000b4a4be46f81242f9ee785e0ebf0604606c15f92cb54a59893a741ec0c AS weaver
