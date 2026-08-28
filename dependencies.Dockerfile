# This is a renovate-friendly source of Docker images.
FROM busybox:musl@sha256:32b5cdad7cce41dfd53d0ae06baebcf8357a147ee7694dc706911c373bc30c37 AS busybox-musl
FROM davidanson/markdownlint-cli2:v0.23.2@sha256:839558fd0d36c46da0e01ea84fd1d20a2822b5a8a60c16dc9708f0bb7c9e903b AS markdown
FROM gradle:9.7.1-jdk21-noble@sha256:153b5cbc7fa81767329b52f741ac63027710fed12624a0014ad1849d6a02f755 AS gradle-java
FROM ghcr.io/astral-sh/uv:python3.9-trixie-slim@sha256:59f428b4c037de1a08e9af383ebdb9e3a2b89a3f745b08b73816b35f8c88886f AS python39
FROM ghcr.io/astral-sh/uv:python3.14-trixie-slim@sha256:d61b872404ed1a0774e2098b5af64c178b59c99be171db6631455262bb0750b4 AS python314
FROM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS golang
FROM otel/weaver:v0.25.1@sha256:9ad46ca9cd4fa5974b121f886aa3e9946a8ef8ea905001a96c018d21f9db87ca AS weaver
