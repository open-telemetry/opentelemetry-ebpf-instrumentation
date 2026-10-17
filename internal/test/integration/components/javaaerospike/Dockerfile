# Build the Java Aerospike test server.
# Docker command must be invoked from the project root directory.
FROM maven:3.10-eclipse-temurin-21@sha256:1f4555322b25bc65c1ae2b87d0558047754ef766abf9bd8a0df8bd342d136eb5 AS javabuilder

WORKDIR /build

COPY internal/test/integration/components/javaaerospike/pom.xml pom.xml
COPY internal/test/integration/components/javaaerospike/src src/

RUN java -version
RUN mvn -q -e clean package

# The App Image
FROM eclipse-temurin:21-jre@sha256:cff19e6215689161eb6162c11b86b0c60ddf802164f2eaf48d570f8fb79a36c5

EXPOSE 8080

COPY --from=javabuilder /build/target/javaaerospike-1.0.0.jar /javaaerospike.jar
CMD ["java", "-jar", "/javaaerospike.jar"]
