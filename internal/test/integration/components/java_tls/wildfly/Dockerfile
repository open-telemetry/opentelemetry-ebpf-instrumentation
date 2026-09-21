FROM maven:3.9.12-eclipse-temurin-21@sha256:c3c9d3ac4ce8431a3995c0318b8d390f448e693dd4fabc16e9b68d2e1f3d7b46 AS builder

WORKDIR /build

COPY internal/test/integration/components/java_tls/wildfly/pom.xml pom.xml
COPY internal/test/integration/components/java_tls/wildfly/reproducer-ejb reproducer-ejb
COPY internal/test/integration/components/java_tls/wildfly/reproducer-war reproducer-war
COPY internal/test/integration/components/java_tls/wildfly/reproducer-ear reproducer-ear

RUN mvn --batch-mode --no-transfer-progress package -DskipTests

FROM quay.io/wildfly/wildfly:34.0.1.Final-jdk21@sha256:3dbad0b0f1378d5ee72e9b5d62f22475e248b1cec65ccf888ebc021b341f7e0a

COPY --from=builder --chown=jboss:root /build/reproducer-ear/target/reproducer-ear.ear /opt/jboss/wildfly/standalone/deployments/

EXPOSE 8080

CMD ["/opt/jboss/wildfly/bin/standalone.sh", "-b", "0.0.0.0"]
