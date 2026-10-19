# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Base images are pinned by digest per devdocs/dependency-integrity-policy.md.
# They match the ones used by internal/test/integration/components/javaaerospike.
FROM maven:3.10-eclipse-temurin-21@sha256:9b4877723dadf350b452dd97d9a6401e7b56f98fa9dfe420c32ad909989c7e4c AS builder

WORKDIR /build

COPY pom.xml pom.xml
COPY src src/

RUN mvn -q -e clean package

FROM eclipse-temurin:21-jre@sha256:cff19e6215689161eb6162c11b86b0c60ddf802164f2eaf48d570f8fb79a36c5

EXPOSE 8080

COPY --from=builder /build/target/recentlyviewed-1.0.0.jar /recentlyviewed.jar

USER 1000:1000
CMD ["java", "-jar", "/recentlyviewed.jar"]
