FROM maven:3.9.12-eclipse-temurin-21@sha256:c3c9d3ac4ce8431a3995c0318b8d390f448e693dd4fabc16e9b68d2e1f3d7b46 AS javabuilder

# Install Maven
ARG USER_HOME_DIR="/cache"

# Set the working directory to /home/app
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/javakafka-tls/.mvn .mvn/
COPY internal/test/integration/components/javakafka-tls/mvnw mvnw
COPY internal/test/integration/components/javakafka-tls/src src/
COPY internal/test/integration/components/javakafka-tls/pom.xml pom.xml

RUN java -version
RUN ./mvnw -version

# Build
RUN ./mvnw package

# The App Image
FROM eclipse-temurin:25.0.3_9-jre@sha256:04262e8782d6b034ee5d7c1c5d4e8938fcf2063a76b4bfcd84e5d994d09c27bc

EXPOSE 8080

# Copy the native executable into the containers
COPY --from=javabuilder /build/target/javakafka-1.0.0.jar ./javakafka-1.0.0.jar
RUN mkdir certs
COPY internal/test/integration/components/javakafka-tls/certs/kafka.truststore.jks ./certs/
COPY internal/test/integration/components/javakafka-tls/certs/kafka.keystore.jks ./certs/
ENTRYPOINT ["java", "-jar", "javakafka-1.0.0.jar"]
