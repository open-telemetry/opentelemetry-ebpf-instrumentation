FROM maven:3.9.10-eclipse-temurin-17@sha256:cdd737b4dad70ec8543c8022c6e11338cfd7b7c83b1a1cf867d1629a185700d7 AS builder

WORKDIR /build

COPY internal/test/integration/components/javaamqp/pom.xml /build/pom.xml
COPY internal/test/integration/components/javaamqp/src /build/src

RUN mvn -B --no-transfer-progress -DskipTests package

FROM eclipse-temurin:17-jre@sha256:13cc28a6cc72a38ce1f00c906be3580c1a3e604b8984d694f369a96742abc93b

WORKDIR /app
EXPOSE 8080

COPY --from=builder /build/target/javaamqp.jar /app/javaamqp.jar

ENTRYPOINT ["java", "-Djava.net.preferIPv4Stack=true", "-jar", "/app/javaamqp.jar"]
