FROM gradle:9.3.0-jdk21-corretto@sha256:2458e66c572212fd24f55ffecde7b88fafdba81e6017eb741179d80cb03d153a AS builder

WORKDIR /build

# Copy build files
COPY pkg/internal/java .

# Build the project
RUN ./gradlew build --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar /obi-java-agent.jar