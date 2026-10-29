# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Base images are pinned by digest per devdocs/dependency-integrity-policy.md.
# They match the ones used by internal/test/integration/components/javaaerospike.
FROM maven:3.10-eclipse-temurin-21@sha256:c665c1041e0c6e28bc7d1b41254622c79cf0b3ac63b519be8b789b05b6f69661 AS builder

WORKDIR /build

COPY pom.xml pom.xml
COPY src src/

RUN mvn -q -e clean package

FROM eclipse-temurin:21-jre@sha256:f37956012e0cb88400e5b3689aeae2d2d735364c1922ae2225536163b5a99f56

EXPOSE 8080

COPY --from=builder /build/target/recentlyviewed-1.0.0.jar /recentlyviewed.jar

USER 1000:1000
CMD ["java", "-jar", "/recentlyviewed.jar"]
