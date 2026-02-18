FROM maven:3.9.12-eclipse-temurin-21@sha256:67dd489908ce4a87c1bea43c589b00c1121a64c1b0ca0f9f80902963655bdc73 AS javabuilder

# Install tar and gzip to extract the Maven binaries
RUN apt install -y tar gzip

# Install Maven
ARG USER_HOME_DIR="/cache"

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/java_tls/sync_async_tls/src src/
COPY internal/test/integration/components/java_tls/sync_async_tls/pom.xml pom.xml

RUN java -version
RUN mvn -version

# Build
RUN mvn clean package

# The App Image
FROM eclipse-temurin:21.0.10_7-jre@sha256:ff7e4a51821d2ceee20fa05064da366f3c12be8ed18596dd2ad0999b2af3fea0

EXPOSE 8080

# Copy the native executable into the containers
COPY --from=javabuilder /build/target/greeting-service-1.0.0.jar .
CMD [ "java", "-jar", "/greeting-service-1.0.0.jar" ]