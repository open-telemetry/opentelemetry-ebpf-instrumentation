# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Base images are pinned by digest per devdocs/dependency-integrity-policy.md.
# They match the ones used by internal/test/integration/components/javaaerospike.
FROM maven:3.10-eclipse-temurin-21@sha256:d49bca545509b98965a808175862337dfdd24e1a8a4b11005cc8ce0578e52e8c AS builder

WORKDIR /build

COPY pom.xml pom.xml
COPY src src/

RUN mvn -q -e clean package

FROM eclipse-temurin:21-jre@sha256:0b99b3376fbb50dbf9c0af8535fdd5b8eb0d3fdfc8b1e4967f383b6919f6901a

EXPOSE 8080

COPY --from=builder /build/target/recentlyviewed-1.0.0.jar /recentlyviewed.jar

USER 1000:1000
CMD ["java", "-jar", "/recentlyviewed.jar"]
