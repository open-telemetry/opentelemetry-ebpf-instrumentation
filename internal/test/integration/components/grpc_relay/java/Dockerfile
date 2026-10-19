FROM maven:3.10-eclipse-temurin-17@sha256:39410d47e240f9177259242e63bf78232808ed77968ebf7e3957b0fa4656f31d AS builder
WORKDIR /app
COPY internal/test/integration/components/grpc_relay/java/pom.xml .
RUN mvn dependency:go-offline -B
COPY internal/test/integration/components/grpc_relay/java/src src
RUN mvn package -DskipTests -B

FROM eclipse-temurin:17-jre@sha256:ff692acf872589e72ca71b416b3e949ec19f35ebe8abb5365d2f31bce298e762
WORKDIR /app
COPY --from=builder /app/target/grpc-relay-java-1.0-SNAPSHOT.jar relay.jar
ENTRYPOINT ["java", "-jar", "relay.jar"]
