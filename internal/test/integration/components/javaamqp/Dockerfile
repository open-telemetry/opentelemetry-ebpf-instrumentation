FROM maven:3.9.10-eclipse-temurin-17@sha256:3f87b585f681619f5b27373461123425a095101ef0929d2cf15ad1888aeed7ff AS builder

WORKDIR /build

COPY internal/test/integration/components/javaamqp/pom.xml /build/pom.xml
COPY internal/test/integration/components/javaamqp/src /build/src

RUN mvn -B --no-transfer-progress -DskipTests package

FROM eclipse-temurin:17-jre@sha256:55f9905b45a83a43aba875de8ad1ffc7b635813ae6bc0830d076f7fd086da48e

WORKDIR /app
EXPOSE 8080

COPY --from=builder /build/target/javaamqp.jar /app/javaamqp.jar

ENTRYPOINT ["java", "-Djava.net.preferIPv4Stack=true", "-jar", "/app/javaamqp.jar"]
