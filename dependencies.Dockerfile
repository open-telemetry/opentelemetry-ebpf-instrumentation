# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:8635836765b0c4c43970660219739baa58b0883c2e429e4b8918f7dd1519455c AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.23.0@sha256:97996d59837fa7cc27fc5f0e16d72eae71d0cefee15c437ee1d7cdbccb5552be AS markdown
FROM gradle:9.6.1-jdk21-noble@sha256:79b27b5ea2d30a9e2d044098b7bd83bc15d22611166cb88eecf11a6501484c82 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:68ac336dbcebb8b86373104dcff5f7e563e08ae69034fb0be46d7e528ae606e9 AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:f561c40cfa19e4605627176a1684f29832a0225665c5253bae569fdc20f1129a AS python314
FROM golang:1.26.4@sha256:f96cc555eb8db430159a3aa6797cd5bae561945b7b0fe7d0e284c63a3b291609 AS golang
FROM otel/weaver:v0.24.2@sha256:d1fb16d279f39810c340fbbf1cf9e5e995a3a9cefa531938e9012437e3bc00c1 AS weaver
