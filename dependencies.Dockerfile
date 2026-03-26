# This is a renovate-friendly source of Docker images.
FROM davidanson/markdownlint-cli2:v0.22.0@sha256:ea33f1f6a0f062f88a3dddfc49f6d6b5621648a93a0ff49a58bf8ac5a15330b9 AS markdown
FROM gradle:9.3.1-jdk21-noble@sha256:f3784cc59d7fbab1e0ddb09c4cd082f13e16d3fb8c50b7922b7aeae8e9507da5 AS gradle-java
