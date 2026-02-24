FROM maven:3.9.12-eclipse-temurin-21@sha256:c3c9d3ac4ce8431a3995c0318b8d390f448e693dd4fabc16e9b68d2e1f3d7b46 AS javabuilder

# Install tar and gzip to extract the Maven binaries
RUN apt install -y tar gzip

# Install Maven
ARG USER_HOME_DIR="/cache"

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/java_tls/netty_tls/src src/
COPY internal/test/integration/components/java_tls/netty_tls/pom.xml pom.xml

RUN java -version
RUN mvn -version

# Build
RUN mvn clean package

# The App Image
FROM eclipse-temurin:21.0.10_7-jre@sha256:34a58218d838035428163eb35abb629944c5906d1bedcfef8bc8864cce11dfe5

EXPOSE 8080

# Copy the native executable into the containers
COPY --from=javabuilder /build/target/http-client-demo-1.0.0.jar .
CMD [ "java", "-jar", "/http-client-demo-1.0.0.jar" ]