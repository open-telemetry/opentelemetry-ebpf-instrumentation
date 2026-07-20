# Build the Java Aerospike test server.
# Docker command must be invoked from the project root directory.
FROM maven:3.9-eclipse-temurin-21@sha256:d7e7f57407437c014571f1ad5a9955f03fc3edcb1d964067ef351fa38e798665 AS javabuilder

WORKDIR /build

COPY internal/test/integration/components/javaaerospike/pom.xml pom.xml
COPY internal/test/integration/components/javaaerospike/src src/

RUN java -version
RUN mvn -q -e clean package

# The App Image
FROM eclipse-temurin:21-jre@sha256:8ec353b20d3aab0758572236b81b967c7077c40c4d0819ce97f9a1329d684603

EXPOSE 8080

COPY --from=javabuilder /build/target/javaaerospike-1.0.0.jar /javaaerospike.jar
CMD ["java", "-jar", "/javaaerospike.jar"]
