# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Base images are pinned by digest per devdocs/dependency-integrity-policy.md.
# They match the ones used by internal/test/integration/components/javaaerospike.
FROM maven:3.10-eclipse-temurin-21@sha256:1f4555322b25bc65c1ae2b87d0558047754ef766abf9bd8a0df8bd342d136eb5 AS builder

WORKDIR /build

COPY pom.xml pom.xml
COPY src src/

RUN mvn -q -e clean package

FROM eclipse-temurin:21-jre@sha256:cff19e6215689161eb6162c11b86b0c60ddf802164f2eaf48d570f8fb79a36c5

EXPOSE 8080

COPY --from=builder /build/target/recentlyviewed-1.0.0.jar /recentlyviewed.jar

USER 1000:1000
CMD ["java", "-jar", "/recentlyviewed.jar"]
