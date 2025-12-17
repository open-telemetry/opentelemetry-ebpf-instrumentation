FROM gradle:9.2.1-jdk21-corretto AS builder

WORKDIR /build

# Copy build files
COPY pkg/internal/java .

# Build the project
RUN ./gradlew build --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar /obi-java-agent.jar