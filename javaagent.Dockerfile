FROM gradle:9.2.1-jdk21-corretto@sha256:3392a25fbe142defde5a13ec7e7171cac8c08ec6bcec00b44705d9a24b544fa3 AS builder

WORKDIR /build

# Copy build files
COPY pkg/internal/java .

# Build the project
RUN ./gradlew build --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar /obi-java-agent.jar