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
FROM eclipse-temurin:21.0.10_7-jre@sha256:34a58218d838035428163eb35abb629944c5906d1bedcfef8bc8864cce11dfe5

EXPOSE 8080

# Copy the native executable into the containers
COPY --from=javabuilder /build/target/javakafka-1.0.0.jar ./javakafka-1.0.0.jar
RUN mkdir certs
COPY internal/test/integration/components/javakafka-tls/certs/kafka.truststore.jks ./certs/
COPY internal/test/integration/components/javakafka-tls/certs/kafka.keystore.jks ./certs/
ENTRYPOINT ["java", "-jar", "javakafka-1.0.0.jar"]
