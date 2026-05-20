FROM maven:3.9.10-eclipse-temurin-17@sha256:3f87b585f681619f5b27373461123425a095101ef0929d2cf15ad1888aeed7ff AS builder

WORKDIR /build

COPY internal/test/integration/components/javaamqp/pom.xml /build/pom.xml
COPY internal/test/integration/components/javaamqp/src /build/src

RUN mvn -B --no-transfer-progress -DskipTests package

FROM eclipse-temurin:25.0.3_9-jre@sha256:db3011b348ad87ced055afe5145238d87a3d8f0e8f23eb4d0cd8cecb4659b085

WORKDIR /app
EXPOSE 8080

COPY --from=builder /build/target/javaamqp.jar /app/javaamqp.jar

ENTRYPOINT ["java", "-Djava.net.preferIPv4Stack=true", "-jar", "/app/javaamqp.jar"]
