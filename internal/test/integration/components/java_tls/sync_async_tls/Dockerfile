FROM maven:3.9.12-eclipse-temurin-21@sha256:c3c9d3ac4ce8431a3995c0318b8d390f448e693dd4fabc16e9b68d2e1f3d7b46 AS javabuilder

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
FROM eclipse-temurin:25.0.3_9-jre@sha256:7ea65de6187ad8fbcc0ad155950c38664a7371148bb3ccf1ec1e1b286b44ad08

EXPOSE 8080

# Copy the native executable into the containers
COPY --from=javabuilder /build/target/greeting-service-1.0.0.jar .
CMD [ "java", "-jar", "/greeting-service-1.0.0.jar" ]