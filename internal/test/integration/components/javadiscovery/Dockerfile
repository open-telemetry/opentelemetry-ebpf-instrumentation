# Dockerfile that will build a container sending Redis traffic from a JVM whose
# attach mechanism is disabled, so agent injection cannot complete.
# Docker command must be invoked from the project root directory
FROM eclipse-temurin:21@sha256:efd34b940f2d5a621605c8531c2afb7759c936b6c2ef637a69aa3bf3e1e789d1 AS builder
WORKDIR /app
COPY internal/test/integration/components/javadiscovery/JavaRedisClient.java .
RUN javac -d /app/classes JavaRedisClient.java

FROM eclipse-temurin:21@sha256:efd34b940f2d5a621605c8531c2afb7759c936b6c2ef637a69aa3bf3e1e789d1
WORKDIR /app
COPY --from=builder /app/classes /app/classes
USER 0:0
CMD ["java", "-XX:+DisableAttachMechanism", "-cp", "/app/classes", "JavaRedisClient"]
