FROM maven:3.10.0-eclipse-temurin-21@sha256:1f4555322b25bc65c1ae2b87d0558047754ef766abf9bd8a0df8bd342d136eb5 AS javabuilder

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
