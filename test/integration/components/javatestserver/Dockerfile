FROM ghcr.io/graalvm/native-image:ol8-java17-22@sha256:d55ebb6eec6751b87ce9d34ab1004fa088d227d90d3edb4d9b3a994e54ac285a AS javabuilder

# Install tar and gzip to extract the Maven binaries
RUN microdnf update \
 && microdnf install --nodocs \
    tar \
    gzip \
 && microdnf clean all \
 && rm -rf /var/cache/yum

# Install Maven
ARG USER_HOME_DIR="/cache"

ENV JAVA_HOME /usr/lib64/graalvm/graalvm22-ce-java17

# Set the working directory to /home/app
WORKDIR /build

# Copy the source code into the image for building
COPY test/integration/components/javakafka/.mvn .mvn/
COPY test/integration/components/javakafka/mvnw mvnw
COPY test/integration/components/javatestserver/src src/
COPY test/integration/components/javatestserver/pom.xml pom.xml

RUN java -version
RUN ./mvnw -version

# Build
RUN ./mvnw -Pnative native:compile

# The App Image
FROM debian:bookworm-slim@sha256:7e490910eea2861b9664577a96b54ce68ea3e02ce7f51d89cb0103a6f9c386e0

EXPOSE 8085

# Copy the native executable into the containers
COPY --from=javabuilder /build/target/greeting-service ./greeting
ENTRYPOINT ["/greeting"]