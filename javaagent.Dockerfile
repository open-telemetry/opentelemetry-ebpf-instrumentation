FROM gradle:9.3.1-jdk21-noble@sha256:f3784cc59d7fbab1e0ddb09c4cd082f13e16d3fb8c50b7922b7aeae8e9507da5 AS builder

# Use Azure mirror for faster downloads on GitHub Actions runners (actions/runner-images#7048)
RUN sed -i 's|archive.ubuntu.com|azure.archive.ubuntu.com|g' /etc/apt/sources.list.d/*.list && \
    apt update && apt install -y clang llvm

WORKDIR /build

# Copy build files
COPY pkg/internal/java .

# Build the project
RUN gradle build --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar /obi-java-agent.jar