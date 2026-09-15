# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:32b5cdad7cce41dfd53d0ae06baebcf8357a147ee7694dc706911c373bc30c37 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.23.2@sha256:839558fd0d36c46da0e01ea84fd1d20a2822b5a8a60c16dc9708f0bb7c9e903b AS markdown
FROM gradle:9.7.1-jdk21-noble@sha256:5c9d1de39fa1779945bd7b1e1c7872150480832a268ecfa3bfed119bb752ac04 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:66415617f04138bab4674f8c7a3f148410c6d1f632e751f4fe3a84825b87574a AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:70d929693dc74ea71d4e510d79e987b5de0723d98439ca7a7196f910055438b0 AS python314
FROM golang:1.27.1@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea AS golang
FROM otel/weaver:v0.26.1@sha256:9094862c0ab261bdbcb079bb981f9a573b3659b130a6d2ab8616eca6ba37aaec AS weaver
